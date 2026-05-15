/* =============================================================================
 * six_param_realtime.js  (v8 — 六参数: 含 X-Medusa 实时校验)
 *
 * 六参数可追踪性:
 *   K (Khronos)   : 无依赖, 严格对比
 *   A (Argus)     : 从 Khronos 推, 严格对比
 *   H (Helios)    : ★ 28/32 严格 + 4/32 nonce (HEAD = rand())
 *   G (Gorgon)    : raw_ptr ASLR, 格式校验
 *   L (Ladon)     : reg7 运行时, 格式校验
 *   M (Medusa)    : ★★★ HEAD[i] = SHA1(s4B‖"1128"‖t4B)[i] ⊕ K[i] ⊕ C[i%4]
 *                   K = 20B device constant (K[0:4]=0), C = counter_u32_LE
 *                   MID = [PRNG 2B][000d][GF(2⁸) 13B], BODY = sponge 292B
 *                   52B GF input = session constant (Block C = heap ptr, 非 hash!)
 *                   需 session_4b (SHA-1 hook 自动捕获)
 *
 * Medusa hook:
 *   - SHA-1 @ 0x248480: 12B input → session_4B 自动捕获
 *   - h0 handler @ 0x2b1028: 首个 Init h0 捕获 RF[6], RF[9] (via x23)
 *   - sign entry gate: 重置 per-sign 状态
 *
 * v8 变更: Block C (GET) = session constant 确证; 修正 bridge 输出统计
 * =============================================================================
 */
'use strict';

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  配置                                                                       ║
// ╚══════════════════════════════════════════════════════════════════════════╝

const CONFIG = {
    module_name: 'libmetasec_ml.so',

    off_sub_2A6E38:   0x2A6E38,
    off_sub_29D950:   0x29D950,
    off_sub_246EB8:   0x246EB8,
    off_dword_3D5DF0: 0x3D5DF0,

    install_time: '1588093228',
    aid: '1128',

    // ─── 算法运行所需的外部输入 ───────────────────────────────────────────
    // 如果你已经通过其它方式知道设备 cdid, 直接填在这里; 否则留空由 MD5
    // hook 自动发现 (见 hook sub_246EB8). 抖音设备 cdid 是 32 字符小写 hex.
    cdid: '',

    // URL 参数的排序策略 — Helios 依赖这个.
    //   'none' : 保留 URL 原顺序 (推荐, 抖音多数签名协议如此)
    //   'asc'  : 按 key 字典序升序
    //   'desc' : 降序
    sort_params: 'none',

    // ─── 调试 ─────────────────────────────────────────────────────────────
    log_raw_args:        false,
    log_gorgon_detail:   true,
    log_sign_result:     true,
    log_md5_inputs:      false,   // 打印所有 MD5 调用 (很吵)
    log_md5_first_only:  true,    // 只打印每个 sign 周期内第一次 MD5 调用
    max_sign_result_len: 32768,
};

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  模块基址                                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

function findModuleBase(name) {
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(name);
        if (m) return m.base;
    }
    if (typeof Process.getModuleByName === 'function') {
        try {
            const m = Process.getModuleByName(name);
            if (m) return m.base;
        } catch (e) {}
    }
    if (typeof Module.findBaseAddress === 'function') {
        return Module.findBaseAddress(name);
    }
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
        if (mods[i].name === name) return mods[i].base;
    }
    return null;
}

const base = findModuleBase(CONFIG.module_name);
if (!base) {
    throw new Error('[!] ' + CONFIG.module_name + ' not loaded yet');
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  工具                                                                       ║
// ╚══════════════════════════════════════════════════════════════════════════╝

function log(text)             { send({ kind: 'log',       text: text }); }
function discover(what, value) { send({ kind: 'discovery', what: what, value: value }); }

function extractSortedParams(url) {
    const qIdx = url.indexOf('?');
    if (qIdx < 0) return '';
    const qs = url.substring(qIdx + 1);
    const hashIdx = qs.indexOf('#');
    const pure = (hashIdx >= 0 ? qs.substring(0, hashIdx) : qs);
    const pairs = pure.split('&').filter(Boolean);
    if (CONFIG.sort_params === 'asc' || CONFIG.sort_params === 'desc') {
        const dir = CONFIG.sort_params === 'asc' ? 1 : -1;
        pairs.sort(function(a, b) {
            const ka = a.split('=', 1)[0];
            const kb = b.split('=', 1)[0];
            return (ka < kb ? -1 : (ka > kb ? 1 : 0)) * dir;
        });
    }
    // 'none' → 保留原顺序
    return pairs.join('&');
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  读取签名结果字符串                                                         ║
// ╚══════════════════════════════════════════════════════════════════════════╝

function tryReadCStr(ptr, maxLen) {
    try {
        if (!ptr || ptr.isNull()) return null;
        const s = ptr.readCString(maxLen);
        if (s && s.length > 0) return s;
    } catch (e) {}
    return null;
}

function looksLikeSignResult(s) {
    if (!s || s.length < 20) return false;
    return s.indexOf('X-') >= 0 || s.indexOf('\r\n') >= 0 || s.indexOf('\n') >= 0;
}

function readSignResult(retval) {
    if (!retval || retval.isNull()) return null;

    // 策略 1: retval 直接是 char*
    let s = tryReadCStr(retval, CONFIG.max_sign_result_len);
    if (looksLikeSignResult(s)) {
        return { mode: 'cstring', text: s };
    }

    // 策略 2: retval 指向 std::string / *char**
    try {
        const p1 = retval.readPointer();
        const s2 = tryReadCStr(p1, CONFIG.max_sign_result_len);
        if (looksLikeSignResult(s2)) {
            return { mode: 'deref_cstring', text: s2 };
        }
    } catch (e) {}

    // 策略 3: retval 当 char** 指针数组
    const PTR = Process.pointerSize;
    const texts = [];
    for (let i = 0; i < 16; i++) {
        let p;
        try { p = retval.add(i * PTR).readPointer(); } catch (e) { break; }
        if (p.isNull()) continue;
        const t = tryReadCStr(p, 2048);
        if (t && t.length >= 6) texts.push(t);
    }
    if (texts.length >= 3) {
        return { mode: 'ptr_array', text: texts.join('\n') };
    }

    // 策略 4: 如果 s 非空但不像 sign_result, 仍返回供调试
    if (s && s.length > 0) {
        return { mode: 'cstring_unknown', text: s };
    }
    return null;
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  解析 sign result 为 5 个签名                                                ║
// ║  (来自 hook_metasec_final.js 的 parseSignatureHeaders)                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝

function parseSignResult(raw) {
    const result = { x_khronos: '', x_argus: '', x_helios: '',
                     x_gorgon:  '', x_ladon:  '',
                     x_medusa:  '', x_perseus: '',
                     headers: {} };
    if (!raw) return result;

    const parts = raw.replace(/\r\n/g, '\n').split('\n');

    // 不再用 hasColon 做硬切换: 格式 A (key: val) 和格式 B (key\n val)
    // 会在 32KB 数据里互相干扰 (base64 碰巧含 ":", 或 URL 含 ":"). 改为:
    // 两种格式都解析一遍, 取命中 X-* 头更多的那一组.

    function parseA(parts) {
        const out = [];
        for (let i = 0; i < parts.length; i++) {
            const line = parts[i].trim();
            if (!line) continue;
            const ci = line.indexOf(':');
            if (ci > 0 && ci < 32) {
                const k = line.substring(0, ci).trim();
                const v = line.substring(ci + 1).trim();
                if (k && v) out.push([k, v]);
            }
        }
        return out;
    }

    function parseB(parts) {
        const out = [];
        // 扫描: 当某行是 "X-<Name>" 且下一行非空时, 把它们配对
        for (let i = 0; i + 1 < parts.length; i++) {
            const k = parts[i].trim();
            const v = parts[i + 1].trim();
            if (/^X-[A-Za-z][A-Za-z0-9-]*$/.test(k) && v.length > 0 && v.length < 40000) {
                out.push([k, v]);
                i++;  // 跳过已用的 value 行
            }
        }
        return out;
    }

    const pairsA = parseA(parts);
    const pairsB = parseB(parts);

    function countXHeaders(pairs) {
        let n = 0;
        for (let i = 0; i < pairs.length; i++) {
            if (/^X-/i.test(pairs[i][0])) n++;
        }
        return n;
    }

    const aN = countXHeaders(pairsA);
    const bN = countXHeaders(pairsB);
    const pairs = (bN > aN) ? pairsB : pairsA;

    for (let i = 0; i < pairs.length; i++) {
        const k = pairs[i][0], v = pairs[i][1];
        const lk = k.toLowerCase();
        result.headers[k] = v;
        if (lk === 'x-khronos')      result.x_khronos = v;
        else if (lk === 'x-argus')   result.x_argus   = v;
        else if (lk === 'x-helios')  result.x_helios  = v;
        else if (lk === 'x-gorgon')  result.x_gorgon  = v;
        else if (lk === 'x-ladon')   result.x_ladon   = v;
        else if (lk === 'x-medusa')  result.x_medusa  = v;
        else if (lk === 'x-perseus') result.x_perseus = v;
    }

    // ─── 消毒器 ─────────────────────────────────────────────────────────
    // 即使 parseB 把后续二进制糊到 value 末尾, 每个签名都有确定的字符集
    // 和长度, 从头部截取合法前缀即可. 这比依赖 \r\n 分隔可靠得多.
    //   X-Khronos : 10 位十进制数字
    //   X-Argus   : 8 字符 Base64
    //   X-Helios  : 48 字符 Base64
    //   X-Gorgon  : 52 字符小写 hex
    //   X-Ladon   : 8 字符 Base64
    //   X-Medusa  : Base64 ≤ 600 字符 (典型 436)
    //   X-Perseus : Base64 ≤ 1200 字符 (典型 932)
    function clip(v, re) {
        if (!v) return '';
        const m = v.match(re);
        return m ? m[0] : '';
    }
    result.x_khronos = clip(result.x_khronos, /^[0-9]{10}/);
    result.x_argus   = clip(result.x_argus,   /^[A-Za-z0-9+/]{6}={0,2}/);
    result.x_ladon   = clip(result.x_ladon,   /^[A-Za-z0-9+/]{6}={0,2}/);
    result.x_helios  = clip(result.x_helios,  /^[A-Za-z0-9+/]{46,48}={0,2}/);
    result.x_gorgon  = clip(result.x_gorgon,  /^[0-9a-f]{52}/);
    result.x_medusa  = clip(result.x_medusa,  /^[A-Za-z0-9+/]+={0,2}/);
    result.x_perseus = clip(result.x_perseus, /^[A-Za-z0-9+/]+={0,2}/);

    // ★ 反哺: 把消毒后值同步回 headers, 让日志 brief 不再显示脏长度
    //   (X-Gorgon 后面没 \r\n 时 parseB 会吃进 2000+ 字节的二进制 payload)
    if (result.x_khronos)  result.headers['X-Khronos']  = result.x_khronos;
    if (result.x_argus)    result.headers['X-Argus']    = result.x_argus;
    if (result.x_ladon)    result.headers['X-Ladon']    = result.x_ladon;
    if (result.x_helios)   result.headers['X-Helios']   = result.x_helios;
    if (result.x_gorgon)   result.headers['X-Gorgon']   = result.x_gorgon;
    if (result.x_medusa)   result.headers['X-Medusa']   = result.x_medusa;
    if (result.x_perseus)  result.headers['X-Perseus']  = result.x_perseus;

    result._format = (bN > aN) ? 'B' : 'A';
    result._xheader_count = Math.max(aN, bN);
    return result;
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  共享状态                                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

let gSeq            = 0;
let gDiscoveredCdid = null;

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  HOOK 1: sub_246EB8 — MD5 wrapper (cdid 自动发现)                          ║
// ║                                                                             ║
// ║  抖音 libmetasec_ml.so 在 sign 管线里多次调用 MD5; 第一次调用的输入通常    ║
// ║  是 "url + sorted_params + cdid", 尾部就是 cdid (32 小写 hex).             ║
// ║                                                                             ║
// ║  ABI 不确定, 尝试两种布局:                                                  ║
// ║    (a) md5(data_ptr, len)                                                   ║
// ║    (b) md5(ctx_ptr, data_ptr, len)                                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝

let gMd5CallCount   = 0;      // 每次 sub_2A6E38 进入时重置
let gMd5Preimage    = '';     // ★ 本次签名中 MD5(url+params+cdid) 的原文
let gMd5Preimages   = [];     // ★ 本次签名所有 MD5 输入 (调试)
let gHeliosHeadHex  = '';     // ★ md5#2 之前 4 字节 = HEAD (源头实为 rand())
let gMd5Digests     = [];     // ★ HEAD 来源审查 (历史遗物 — 见下文注): 全 MD5 digest
let gGorgonHash20Hex = '';    // ★ HEAD 来源审查 (历史遗物): sub_29D950 之 hash20
// ─────────────────────────────────────────────────────────────────────────
// ★★★ 关于"HEAD 来源审查" (gMd5Digests + gGorgonHash20Hex) 之说明:
//
//   v4-v5 时期试图证 HEAD = MD5(某 input)[某偏移:+4] 或 = hash20[某偏移:+4].
//   v6 严审 (libmetasec 0x26FF30 disasm + readelf -r) 已证:
//       HEAD = bionic libc rand() 之返回, 不是任何 input 之 hash.
//
//   故 HEAD 来源审查永远不会命中. 但保留此审查代码:
//     (1) 防御性: 若某日真现"HEAD == 某 hash 之片段", 结论须重审 (极不可能).
//     (2) 文档化: 让后人看到此审查皆失败, 印证 HEAD 是 rand 之事实.
//     (3) 调试: 仍可用于查 md5 / Gorgon 调用之全貌.
// ─────────────────────────────────────────────────────────────────────────

Interceptor.attach(base.add(CONFIG.off_sub_246EB8), {
    onEnter: function(args) {
        gMd5CallCount++;
        this.callIdx = gMd5CallCount;
        try { this.x2 = args[2]; } catch (e) { this.x2 = null; }   // ★ 输出 digest 指针

        if (gMd5CallCount === 1) {
            log('[md5 hook ★ FIRED] sub_246EB8 第一次被调用 (本轮 sign)');
        }

        // ★ ABI 已知 (经本次日志分析确认):
        //    sub_246EB8(void* data, size_t len, void* out_digest16, /* x3: 残留 */)
        //    x0 = data 指针
        //    x1 = 数据长度 (小整数, 0x8 / 0x80 / 0x30f / 0x1905 ...)
        //    x2 = 16 字节摘要输出缓冲 (在栈上 0x7c4df8xxxx 一带)
        //    x3 = "on_varia" 字样的常量/残留, 不用
        //
        //    之前我们假设 (data, len) 或 (ctx, data, len), 都半对 — 这里确认了.

        // ★ 逐字节读取器: Memory.readByteArray 对某些堆地址整体失败,
        //   但逐字节 readU8 + per-byte try/catch 能至少拿到头几字节,
        //   足够判断是不是 URL 字符串.
        function readAsciiSafe(ptr, max) {
            let s = '';
            for (let i = 0; i < max; i++) {
                let b;
                try { b = ptr.add(i).readU8(); } catch (e) { break; }
                s += (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.';
            }
            return s;
        }
        function readBytesSafe(ptr, max) {
            const out = [];
            for (let i = 0; i < max; i++) {
                let b;
                try { b = ptr.add(i).readU8(); } catch (e) { break; }
                out.push(b);
            }
            return out;
        }

        // 真实 len = x1
        let realLen = 0;
        try { realLen = args[1].toInt32(); } catch (e) {}
        if (realLen <= 0 || realLen > 16384) realLen = 0;

        // ★ 无条件 dump (前 3 次调用) 用于调试
        if (gMd5CallCount <= 3) {
            const readLen = realLen > 0 ? Math.min(realLen, 200) : 128;
            const a0 = readAsciiSafe(args[0], readLen);
            log('[md5#' + gMd5CallCount + ' ARGS] ' +
                'x0=' + args[0] + ' x1=0x' + realLen.toString(16) +
                ' (' + realLen + ') x2=' + args[2]);
            log('    *x0[:' + readLen + '] ascii="' +
                a0.substr(0, 180) + (a0.length > 180 ? '..."' : '"'));
        }

        // 只要能用 x1 读出字节, 就往下走 preimage / cdid 逻辑
        if (realLen < 4) return;

        const bytesArr = readBytesSafe(args[0], realLen);
        if (bytesArr.length === 0) return;

        // hex 预览
        let hex = '';
        for (let i = 0; i < Math.min(bytesArr.length, 64); i++) {
            hex += bytesArr[i].toString(16).padStart(2, '0');
        }
        // ASCII 视图
        let ascii = '';
        for (let i = 0; i < bytesArr.length; i++) {
            const c = bytesArr[i];
            ascii += (c >= 0x20 && c <= 0x7E) ? String.fromCharCode(c) : '.';
        }
        // UTF-8
        let txt = '';
        try { txt = Memory.readUtf8String(args[0], realLen) || ''; } catch (e) {}
        // 如果 UTF-8 拿不到但 ascii 几乎全可打印, 认为它是纯 ASCII
        if (!txt && ascii.indexOf('.') < ascii.length / 10) {
            txt = ascii;  // 借用 ascii 作 text 字段
        }

        if (gMd5Preimages.length < 10) {
            gMd5Preimages.push({
                idx: gMd5CallCount, len: realLen,
                text:  txt,             // ★ 完整 (不截断, 用于 HEAD 搜索)
                ascii: ascii,           // ★ 完整
                hex:   hex,
            });
        }

        // ★ md5#1 (URL+params) 尾部 dump — 看是否含 URL_path 或其它加密字段
        if (gMd5CallCount === 1 && realLen > 200) {
            const tail_start = Math.max(0, realLen - 200);
            log('[md5#1 input TAIL ascii] (off=' + tail_start + ') "' +
                ascii.substr(tail_start, 200) + '"');
        }

        // ★★★ Helios HEAD 捕获 (md5#2 之前 4 字节)
        //
        //   md5#2 输入 = 8 字节, 末 4 字节 = "1128" (aid).
        //   前 4 字节即 HEAD — 此 HEAD 实为 client 之 rand() 调用结果,
        //   在 vm3.outer1 (pk=0x23) 之 CF21 handler 里, 由 0x26FF30 之
        //   bl 0x34C060 (= PLT → rand@LIBC) 产生, 写入 m11+0x20.
        //
        //   md5#2 调用是 SPECK key 派生之第一步 (md5hex = MD5(HEAD || aid)),
        //   故 md5#2 input 之前 4 字节 == HEAD. 这是 hook HEAD 之最简单点.
        //
        //   ★ 此处 hook 出之 HEAD 仍是逐次签名变化之随机值, 离线复现
        //     必须从此处抓取, 或 使用本地 rand() / urandom.
        if (!gHeliosHeadHex && realLen === 8 && bytesArr.length >= 8) {
            const tail = String.fromCharCode(bytesArr[4], bytesArr[5],
                                             bytesArr[6], bytesArr[7]);
            if (tail === CONFIG.aid) {
                gHeliosHeadHex = bytesArr.slice(0, 4)
                    .map(function(b) { return b.toString(16).padStart(2, '0'); })
                    .join('');
                log('[helios_head ★ 捕获] md5#' + gMd5CallCount +
                    ' HEAD=' + gHeliosHeadHex +
                    ' (源头实为 client rand(), 此乃 SPECK key 派生 md5#2 之入口)');

                // ★★★ HEAD 来源审查 (历史遗物 — 永远不会命中)
                //
                //   v4-v5 时期之假设: HEAD 由某个 input 经 hash 推得.
                //   v6 严审已破: HEAD = libc rand() 之返回值, 非任何 hash.
                //
                //   故下面之审查永远 silent. 保留以:
                //     (1) 防御性确证 — 若某日真命中, 须重审 HEAD 之结论.
                //     (2) 让人见到审查皆不命中, 印证 rand() 之论.
                //   真有疑虑者可单独 disasm libmetasec+0x26FF30 & 验
                //   bl #0x34C060 之 readelf -r 解为 rand@LIBC.
                for (let i = 0; i < gMd5Digests.length; i++) {
                    const d = gMd5Digests[i];
                    if (!d || !d.digest_hex) continue;
                    // 试: digest 任意 4 字节滑窗 (offsets 0,4,8,12 — u32 边界)
                    // 试: digest BE/LE swap (整 u32 字节序翻转)
                    const dh = d.digest_hex;  // 32 hex chars = 16 bytes
                    for (let off = 0; off + 4 <= 16; off++) {
                        const win_le = dh.substr(off * 2, 8);
                        if (win_le === gHeliosHeadHex) {
                            log('[HEAD 来源 ⚠ 意外命中 LE] HEAD == md5#' + d.idx +
                                '.digest[' + off + ':' + (off + 4) +
                                ']  (in_len=' + d.input_len + ')');
                            log('  → 注: 此命中极可能是巧合 (4B 全等概率 = 2^-32)');
                            log('  → md5#' + d.idx + ' 完整 digest = ' + dh);
                        }
                        // BE 翻转
                        const win_be = win_le.match(/../g).reverse().join('');
                        if (win_be === gHeliosHeadHex) {
                            log('[HEAD 来源 ⚠ 意外命中 BE] HEAD == BE(md5#' + d.idx +
                                '.digest[' + off + ':' + (off + 4) +
                                '])  (in_len=' + d.input_len + ')');
                            log('  → 注: HEAD 实为 rand(), 此 BE 命中亦是巧合');
                            log('  → md5#' + d.idx + ' 完整 digest = ' + dh);
                        }
                    }
                }

                // HEAD vs Gorgon hash20 (历史遗物, 同上)
                if (gGorgonHash20Hex) {
                    for (let off = 0; off + 4 <= 20; off++) {
                        const win_le = gGorgonHash20Hex.substr(off * 2, 8);
                        if (win_le === gHeliosHeadHex) {
                            log('[HEAD 来源 ⚠ 意外命中 GORGON] HEAD == hash20[' +
                                off + ':' + (off + 4) + ']  (巧合, HEAD 实为 rand)');
                            log('  → Gorgon hash20 = ' + gGorgonHash20Hex);
                        }
                    }
                }

                // 邻域 hex dump (诊断用, 看 m11 在 md5#2 input 周边之布局)
                try {
                    function dumpHex(start_off, n) {
                        let hex = '';
                        let asc = '';
                        for (let i = 0; i < n; i++) {
                            const b = args[0].add(start_off + i).readU8();
                            hex += b.toString(16).padStart(2, '0');
                            asc += (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.';
                            if (i % 4 === 3) hex += ' ';
                        }
                        return { hex: hex, asc: asc };
                    }
                    const pre = dumpHex(-48, 48);   // 前 48 字节 (含 "1588093228-KEY" 区域)
                    const post = dumpHex(8, 48);    // 后 48 字节
                    log('[md5#2 buf 邻域 HEX (诊断)]');
                    log('  prev[-48..0] hex: ' + pre.hex);
                    log('  prev[-48..0] asc: ' + pre.asc);
                    log('  next[8..56]  hex: ' + post.hex);
                    log('  next[8..56]  asc: ' + post.asc);
                    // 在前后 hex 里搜 HEAD 字符串 — 此搜索可能命中 m11 自身
                    // (因 HEAD 已被写入 m11 +0x20, 故出现在邻域属正常)
                    const head_le = gHeliosHeadHex.replace(/ /g, '');
                    const head_be = head_le.match(/../g).reverse().join('');
                    const all_hex = pre.hex.replace(/ /g, '') + post.hex.replace(/ /g, '');
                    const idx_le = all_hex.indexOf(head_le);
                    const idx_be = all_hex.indexOf(head_be);
                    if (idx_le >= 0) {
                        log('[HEAD 邻域出现 LE] HEAD 在偏移 ' +
                            (idx_le / 2 - 48) + ' (= m11 自身之 HEAD 字段, 正常)');
                    }
                    if (idx_be >= 0) {
                        log('[HEAD 邻域出现 BE] 偏移 ' + (idx_be / 2 - 48));
                    }
                } catch (e) {
                    log('[md5#2 buf 邻域读取失败: ' + e + ']');
                }

                // HEAD 是否出现在 md5#1 input (历史遗物)
                if (gMd5Preimages[0]) {
                    const m1 = gMd5Preimages[0];
                    const txt = (m1.text || m1.ascii || '').toLowerCase();
                    const idx = txt.indexOf(gHeliosHeadHex);
                    if (idx >= 0) {
                        log('[HEAD ⚠ 出现于 md5#1 input] 偏移 ' + idx +
                            ' (4B 巧合概率 ~ in_len/2^32)');
                        log('  上下文="' +
                            txt.substr(Math.max(0, idx - 16), 32 + gHeliosHeadHex.length) +
                            '"');
                    }
                    // 也试 BE byte-swap
                    const head_be_bytes = gHeliosHeadHex.match(/../g).reverse().join('');
                    const idx2 = txt.indexOf(head_be_bytes);
                    if (idx2 >= 0) {
                        log('[HEAD ⚠ 出现于 md5#1 BE] 偏移 ' + idx2);
                    }
                }
            }
        }

        if (CONFIG.log_md5_inputs ||
            (CONFIG.log_md5_first_only && gMd5CallCount <= 4)) {
            log('[md5 #' + gMd5CallCount + '] len=' + realLen +
                ' ascii="' + ascii.substr(0, 120) + '"');
        }

        // ★ preimage 捕获
        if (!gMd5Preimage) {
            const domainRe = /(https?:\/\/[^\s\x00-\x1f]+|[a-zA-Z0-9_.-]+\.(?:amemv|snssdk|douyin|tiktok|bytedance)\.[a-z]+[^\s\x00-\x1f]*)/;
            const src = (txt.length > 0) ? txt : ascii;
            const m = src.match(domainRe);
            if (m && m[0].length >= 20) {
                gMd5Preimage = src;
                log('[md5_preimage ★ 捕获] md5#' + gMd5CallCount +
                    ' len=' + src.length);
                log('    preview="' + src.substr(0, 160) +
                    (src.length > 160 ? '..."' : '"'));
            }
        }

        // cdid 自动发现 (32 字符小写 hex)
        if (!gDiscoveredCdid && !CONFIG.cdid) {
            const search_str = (txt.length >= 32) ? txt : ascii;
            const matches = search_str.match(/[0-9a-f]{32}/g);
            if (matches && matches.length > 0) {
                const candidate = matches[matches.length - 1];
                gDiscoveredCdid = candidate;
                discover('cdid', candidate);
                log('[discover ★] cdid = ' + candidate +
                    '  (from md5#' + gMd5CallCount + ')');
            }
        }
    },
    onLeave: function(_retval) {
        // ★★★ HEAD 来源审查: 读 x2 处的 16 字节 digest
        //     md5#1 digest 应该 == HEAD (4 字节) — 即 HEAD = MD5(md5#1_input)[0:4]
        //     这里把所有 digest 都缓存, 等 md5#2 处 HEAD 抓到时再回溯比对.
        if (!this.x2 || this.callIdx > 7) return;
        try {
            const dbytes = [];
            for (let i = 0; i < 16; i++) {
                dbytes.push(this.x2.add(i).readU8());
            }
            const dhex = dbytes.map(function(b) {
                return b.toString(16).padStart(2, '0');
            }).join('');
            // 找对应的 input 长度
            let inLen = 0;
            for (let k = 0; k < gMd5Preimages.length; k++) {
                if (gMd5Preimages[k].idx === this.callIdx) {
                    inLen = gMd5Preimages[k].len;
                    break;
                }
            }
            gMd5Digests.push({
                idx: this.callIdx, digest_hex: dhex, input_len: inLen
            });
            // 前 3 次调用打 digest 简报 (其它太多就不打了)
            if (this.callIdx <= 3) {
                log('[md5 #' + this.callIdx + ' ◀ digest] ' +
                    dhex + ' (in_len=' + inLen + ')');
            }
        } catch (e) {
            // x2 不可读, 静默忽略
        }
    }
});

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  HOOK 2 (可选/已知失败): sub_29D950 — Gorgon 核心                            ║
// ║                                                                             ║
// ║  之前版本试图从 concat_obj + 0x40 读 "raw_ptr 低 2 字节" 用于离线复现       ║
// ║  Gorgon, 但实测该位置是固定值 (0x38, 0x56) 不是真实 raw_ptr.                ║
// ║  真实 raw_ptr = malloc() 返回的堆地址, 要捕获需 hook libc malloc, 开销大.   ║
// ║  既然已改成 Gorgon 格式校验, 此 hook 主要保留用于 a2 调试.                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

if (CONFIG.log_gorgon_detail) {
    Interceptor.attach(base.add(CONFIG.off_sub_29D950), {
        onEnter: function(args) {
            this.a2 = args[1].toInt32() & 0xFFFF;
            // ★ AArch64: X8 是间接结果寄存器, 在 Frida 里通过 context.x8 拿
            //   sub_29D950 的输出: *X8 = ptr_to_24B_struct
            //                      *(X8 + 16) = ptr_to_26B_raw_buf
            //                      raw_buf + 6 = hash20 (20 bytes) ★
            try { this.x8 = this.context.x8; } catch (e) { this.x8 = null; }
        },
        onLeave: function(_retval) {
            // ★★★ 读取 hash20 — HEAD 来源审查关键
            let hash20_hex = '(读取失败)';
            try {
                if (this.x8) {
                    const struct_ptr = this.x8.readPointer();        // *X8
                    const raw_buf = struct_ptr.add(16).readPointer(); // *(*X8 + 16)
                    const bytes = [];
                    for (let i = 0; i < 20; i++) {
                        bytes.push(raw_buf.add(6 + i).readU8());
                    }
                    hash20_hex = bytes.map(function(b) {
                        return b.toString(16).padStart(2, '0');
                    }).join('');
                    gGorgonHash20Hex = hash20_hex;   // ★ 全局保存
                }
            } catch (e) {
                hash20_hex = '(read error: ' + e + ')';
            }
            log('[gorgon_core ◀ hash20] ' + hash20_hex + '  (a2=' + this.a2 + ')');
        }
    });
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  HOOK M: Medusa VM — 捕获 session constants (RF[6], RF[9])               ║
// ║                                                                             ║
// ║  h0 XOR handler @ 0x2b1028 在 VM 执行期间触发.                            ║
// ║  在 Init phase 之第一个 h0, x23+6*8 = RF[6] (session ptr),               ║
// ║  x23+9*8 = RF[9] (sign counter). 这两个值是 session constants.            ║
// ╚══════════════════════════════════════════════════════════════════════════╝

var gMedusaSignActive = false;
var gMedusaH0Count = 0;
var gMedusaRF6 = 0;
var gMedusaRF9 = 0;
var gMedusaSessionCaptured = false;  // RF[6] 只需 1 次/session
var gMedusaPerSignRF9 = 0;          // RF[9] 每 sign 重新捕获 (counter +1/call)
var gMedusaSession4B = '';           // SHA-1 input[0:4] = device constant
var gMedusaGfCalls = [];             // ★ 每 sign 所有 GF(52B) 调用

// ── Hook sub_2A33E0 (GF matrix entry) — 捕获 52B 输入 + 32B 输出 ──────
// sub_2A33E0(ctx, input_52B, output_32B)
// ★ M_total 是 session-specific, 不可用内嵌矩阵计算
// ★ 改为: onEnter 读 input, onLeave 读 output → output[19:32] = MID-E
Interceptor.attach(base.add(0x2A33E0), {
    onEnter: function(args) {
        if (!gMedusaSignActive) return;
        try {
            this._out = args[2];  // output_32B pointer
            var ptr = args[1];
            var hex = '';
            for (var i = 0; i < 52; i++) {
                hex += ('0' + ptr.add(i).readU8().toString(16)).slice(-2);
            }
            this._in52 = hex;
        } catch (e) {
            log('[medusa] GF onEnter error: ' + e);
        }
    },
    onLeave: function(ret) {
        if (!this._out || !this._in52) return;
        try {
            // Read 32B output (MID-E = output[19:32])
            var outHex = '';
            for (var i = 0; i < 32; i++) {
                outHex += ('0' + this._out.add(i).readU8().toString(16)).slice(-2);
            }
            var mideHex = outHex.substring(38);  // bytes[19:32] = hex[38:64]
            gMedusaGfCalls.push({
                input: this._in52,
                output: outHex,
                mide: mideHex
            });
            if (gMedusaGfCalls.length <= 3) {
                log('[medusa] GF#' + gMedusaGfCalls.length +
                    ' out[19:32]=' + mideHex +
                    ' in=' + this._in52.substring(0, 16) + '…');
            }
        } catch (e) {
            log('[medusa] GF onLeave error: ' + e);
        }
    }
});

// ── Hook SHA-1 wrapper (sub_248480) to capture session_4B ──
// sub_248480(data, size, output) — non-OLLVM, clean SHA-1
Interceptor.attach(base.add(0x248480), {
    onEnter: function(args) {
        if (!gMedusaSignActive) return;
        try {
            var sz = args[1].toInt32();
            if (sz === 12 && !gMedusaSession4B) {
                var data = args[0];
                var hex = '';
                for (var i = 0; i < 12; i++) {
                    hex += ('0' + data.add(i).readU8().toString(16)).slice(-2);
                }
                gMedusaSession4B = hex.substring(0, 8);  // first 4B
                log('[medusa] session_4B captured: ' + gMedusaSession4B +
                    ' (SHA-1 input=' + hex + ')');
            }
        } catch (e) {}
    }
});

Interceptor.attach(base.add(0x2b1028), function() {
    if (!gMedusaSignActive) return;
    gMedusaH0Count++;
    // Capture at very first h0 of Init phase (before RF[9] gets overwritten at h0 #2)
    if (gMedusaH0Count === 1) {
        try {
            var x23 = this.context.x23;
            var rf6 = x23.add(6 * 8).readU32() >>> 0;
            var rf9 = x23.add(9 * 8).readU32() >>> 0;
            // Sanity: both should be > 0x10000 (pointers/counters)
            if (rf6 > 0x10000 && rf9 > 0x10000) {
                gMedusaPerSignRF9 = rf9;   // ★ 每 sign 更新
                if (!gMedusaSessionCaptured) {
                    gMedusaRF6 = rf6;
                    gMedusaRF9 = rf9;
                    gMedusaSessionCaptured = true;
                    log('[medusa] session captured: RF[6]=0x' +
                        ('00000000' + rf6.toString(16)).slice(-8) +
                        ' RF[9]=0x' +
                        ('00000000' + rf9.toString(16)).slice(-8));
                }
            }
        } catch (e) { /* VM not active yet */ }
    }
});

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  HOOK 3: sub_2A6E38 — 签名总入口 (retval 是 sign_result 字符串)              ║
// ╚══════════════════════════════════════════════════════════════════════════╝

Interceptor.attach(base.add(CONFIG.off_sub_2A6E38), {
    onEnter: function(args) {
        gMd5CallCount = 0;          // 每次 sign 重置
        gMd5Preimage  = '';          // ★ 本轮 md16 preimage
        gMd5Preimages = [];          // 本轮所有 MD5 输入 (调试)
        gHeliosHeadHex = '';         // ★ 本轮 Helios HEAD
        gMd5Digests   = [];          // ★ 本轮 MD5 输出 digest 缓存 (HEAD 来源审查)
        gGorgonHash20Hex = '';       // ★ 本轮 Gorgon hash20 (HEAD 来源审查)
        gMedusaSignActive = true;    // ★ Medusa VM gate
        gMedusaH0Count = 0;
        gMedusaGfCalls = [];         // ★ reset per-sign GF captures
        this.seq = ++gSeq;
        try { this.url = args[0].readCString(4096) || ''; }
        catch (e) { this.url = ''; }

        // 每次进入先打 heartbeat, 便于看 MD5 hook 是否 "在这之间" 被触发
        log('[sign #' + this.seq + ' ▶ ENTER] ' + this.url.slice(0, 80));

        if (CONFIG.log_raw_args) {
            log('[entry #' + this.seq + '] url=' + this.url.slice(0, 120));
            for (let i = 0; i < 8; i++) {
                try { log('  x' + i + ' = ' + args[i]); } catch (e) {}
            }
        }
    },
    onLeave: function(retval) {
        // ★ 先打 MD5 命中数统计, 便于审计本轮 sign 调用了几次 sub_246EB8
        log('[sign #' + this.seq + ' ◀ LEAVE] sub_246EB8 命中次数=' +
            gMd5CallCount + ', preimage 捕获=' +
            (gMd5Preimage ? '"' + gMd5Preimage.substr(0,60) + '..."' : '(无)'));

        // ★ 从 retval 读签名结果字符串
        const sr = readSignResult(retval);
        let parsed;
        if (sr) {
            parsed = parseSignResult(sr.text);
            if (CONFIG.log_sign_result) {
                // 使用消毒后的签名值长度, 避免 X-Gorgon 显示为 6924 等误导
                const sanitizedLens = {
                    'X-Khronos': parsed.x_khronos.length,
                    'X-Argus':   parsed.x_argus.length,
                    'X-Helios':  parsed.x_helios.length,
                    'X-Gorgon':  parsed.x_gorgon.length,
                    'X-Ladon':   parsed.x_ladon.length,
                    'X-Medusa':  parsed.x_medusa.length,
                    'X-Perseus': parsed.x_perseus.length,
                };
                const keys = Object.keys(parsed.headers || {});
                const brief = keys.map(function(k) {
                    const raw = parsed.headers[k];
                    const rawLen = raw ? raw.length : 0;
                    const sane = sanitizedLens[k];
                    if (sane !== undefined && sane !== rawLen) {
                        return k + '(' + sane + '|raw ' + rawLen + ')';
                    }
                    return k + '(' + rawLen + ')';
                }).join(', ');
                log('[sign_result #' + this.seq + ' mode=' + sr.mode +
                    ' fmt=' + parsed._format +
                    ' x_hdrs=' + parsed._xheader_count +
                    ' total_len=' + sr.text.length + ']');
                log('    headers: ' + brief);
                if (parsed._xheader_count === 0) {
                    log('    raw[:400]: ' + sr.text.substr(0, 400)
                        .replace(/\r/g, '\\r').replace(/\n/g, '\\n'));
                }
            }
        } else {
            log('[sign_result #' + this.seq + '] retval 不可读 (' + retval + ')');
            parsed = { x_khronos: '', x_argus: '', x_helios: '',
                       x_gorgon: '',  x_ladon: '',
                       x_medusa: '',  x_perseus: '',
                       headers: {} };
        }

        // ★ 识别非签名 retval: 必须同时含 X-Khronos + X-Gorgon + X-Argus
        // 这三个头是抖音签名管线产物的"铁证", 缺任一就不是签名结果.
        // 之前 "任一存在即可" 会被 HTTP 响应里的 X-Response-Date /
        // X-Kfc-Cachekey 等 X-* 头误判为有效签名, 本次证据中 HTTP 响应
        // 解析出的 16 个 X-* 头都是响应类, 现在要求三个核心头必须都有.
        const hasSignHeaders = !!(parsed.x_khronos && parsed.x_gorgon &&
                                  parsed.x_argus);
        if (!hasSignHeaders) {
            const missing = (parsed.x_khronos ? '' : 'K ') +
                            (parsed.x_gorgon  ? '' : 'G ') +
                            (parsed.x_argus   ? '' : 'A ');
            log('[sign #' + this.seq + ' ✗ SKIP] 非签名 retval, 缺失 [' +
                missing.trim() + ']; 头: ' +
                Object.keys(parsed.headers || {}).slice(0, 5).join(', ') +
                (Object.keys(parsed.headers || {}).length > 5 ? ' ...' : ''));
            return;
        }

        send({
            kind:               'sample',
            seq:                this.seq,
            url:                this.url,
            sorted_params:      extractSortedParams(this.url),
            cdid:               CONFIG.cdid || gDiscoveredCdid || '',
            install_time:       CONFIG.install_time,
            aid:                CONFIG.aid,
            body_hex:           '',

            // ★ 关键: 直接把 MD5 的原始输入带给 Python, 让它不用猜拼接规则
            md5_preimage:       gMd5Preimage,
            md5_all_inputs:     gMd5Preimages,   // 调试用, 万一 preimage 选错了
            helios_head_hex:    gHeliosHeadHex,  // ★ Helios 的 HEAD (4B hex)

            x_khronos:          parsed.x_khronos,
            x_argus:            parsed.x_argus,
            x_helios:           parsed.x_helios,
            x_gorgon:           parsed.x_gorgon,
            x_ladon:            parsed.x_ladon,
            x_medusa:           parsed.x_medusa || '',
            x_perseus:          parsed.x_perseus || '',

            // ★ Medusa session constants (captured from VM h0 handler)
            medusa_rf6:         gMedusaSessionCaptured ? gMedusaRF6 : null,
            medusa_rf9:         gMedusaPerSignRF9 || (gMedusaSessionCaptured ? gMedusaRF9 : null),
            medusa_session_4b:  gMedusaSession4B || null,
            medusa_gf_calls:    gMedusaGfCalls.length > 0 ? gMedusaGfCalls : null,

            // 运行时常量 (G/L) - 由于 ASLR, 不可稳定复现, 走格式校验路径
            gorgon_a2:          null,
            gorgon_raw_ptr_b0:  null,
            gorgon_raw_ptr_b1:  null,
            ladon_reg7:         null,
            ladon_prng:         null,

            sign_result_raw:    sr ? sr.text.substr(0, 2000) : '',
            sign_result_mode:   sr ? sr.mode : 'failed',
        });
        gMedusaSignActive = false;  // ★ Medusa gate off
    }
});

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  全局 MD5 探针 (可选) — 若 sub_246EB8 命中 0 次, 本探针可找出真实 MD5     ║
// ║                                                                             ║
// ║  扫下列导出名, 凡找到就 hook, 命中时打 [md5_probe] 日志                    ║
// ╚══════════════════════════════════════════════════════════════════════════╝

const MD5_PROBE_NAMES = [
    'MD5',            'MD5_Init',     'MD5_Update',   'MD5_Final',
    'MD5Init',        'MD5Update',    'MD5Final',
    'CC_MD5',         'CC_MD5_Init',  'CC_MD5_Update', 'CC_MD5_Final',
    'EVP_DigestInit', 'EVP_DigestUpdate', 'EVP_DigestFinal',
];
const MD5_PROBE_LIBS = [
    'libcrypto.so',        'libcrypto.so.1.1',  'libssl.so',
    'libmetasec_ml.so',    'libcms.so',         'libsscronet.so',
    'boringssl.so',        'libc.so',
];

(function installMd5Probes() {
    let installed = 0;
    for (let li = 0; li < MD5_PROBE_LIBS.length; li++) {
        const lib = MD5_PROBE_LIBS[li];
        for (let ni = 0; ni < MD5_PROBE_NAMES.length; ni++) {
            const name = MD5_PROBE_NAMES[ni];
            let p = null;
            try { p = Module.findExportByName(lib, name); } catch (e) {}
            if (!p) continue;
            try {
                Interceptor.attach(p, {
                    onEnter: function(args) {
                        // 前 3 次调用各打一条, 避免刷屏
                        if (this._probeLogged) return;
                        this._probeLogged = true;
                        let preview = '';
                        try {
                            const len = args[1].toInt32();
                            if (len > 0 && len < 2048) {
                                preview = Memory.readUtf8String(args[0], len) || '';
                            }
                        } catch (e) {}
                        log('[md5_probe] ' + lib + ':' + name + ' fired' +
                            (preview ? ', input≈ "' + preview.substr(0, 80) + '"' : ''));
                    }
                });
                installed++;
            } catch (e) {}
        }
    }
    if (installed > 0) {
        console.log('[+] installed ' + installed + ' generic MD5 probe hook(s)');
    }
})();


function waitVerdict() {
    recv('verdict', function onVerdict(msg) {
        // Python 端已打印详细 verdict, JS 端不再重复
        waitVerdict();
    });
}
waitVerdict();

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  就绪日志                                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

console.log('[+] six_param_realtime (v8 / SHA-1⊕K⊕C) armed');
console.log('    module = ' + CONFIG.module_name + ' @ ' + base);
console.log('    sign   = ' + base.add(CONFIG.off_sub_2A6E38));
console.log('    gorgon = ' + base.add(CONFIG.off_sub_29D950));
console.log('    md5    = ' + base.add(CONFIG.off_sub_246EB8));
console.log('    prng   = ' + base.add(CONFIG.off_dword_3D5DF0));
console.log('    medusa_h0 = ' + base.add(0x2b1028));
console.log('');
console.log('[cfg] sort_params = ' + CONFIG.sort_params);
console.log('[cfg] cdid        = ' + (CONFIG.cdid ? CONFIG.cdid : '(待 MD5 hook 自动发现)'));
console.log('');
console.log('[info] 运行时常量追踪策略:');
console.log('  K / A            : 完全确定性, 严格对比');
console.log('  H                : 依赖 cdid + sorted_params, 严格对比 (best-effort)');
console.log('  G (raw_ptr ASLR) : 格式校验');
console.log('  L (reg7 运行时)  : 格式校验');
console.log('  M (Medusa)       : HEAD SHA-1⊕K⊕C 严格 20/20 + MID/BODY 结构校验');