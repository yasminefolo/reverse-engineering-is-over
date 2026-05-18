# Medusa v31m BODY 離線生成 — 完整知識彙總 v3

> 更新日期: 2026-04-29 (v134b + v6 六元全勝)
> 基於: v1-v98 共 98 輪 Frida 實驗 + libmetasec_ml.so 離線反彙
> SO 文件: libmetasec_ml.so (ARM64, .text 0x34c740 bytes)

---

## 總判決: ≈99% (v6: 六元全勝! K✓A✓H✓G✓L✓M✓ 28/28, HEAD 公式完全攻克)

Layer 1 ARX sponge permutation **全部 34 operations 皆有 closed-form formula**:
- 32 algebraic (AND/NOT/XOR/ADD/ROL/COPY/MAJ) + 1 counter + 1 rate_buffer_read
- **46/46 rounds × 21 slots × 2 signs = 1932 RF computations, ALL PASS**
- ★ RF[16] = MAJ(RF[29], RF[20], RF[28]) — SM3 compression function primitive! (92/92 verified)
- 1 round = 20 handler dispatches + KS compound
- ★ URL absorption = sponge absorb (64B blocks XOR into state + permute)
- ★ Rate buffer = sponge state[0x44+4*i], sequential read (v130: 64/64 URL match)
- ★ KS compound = 5 register copies (h=169 COPY, 92/92 verified) + 0x2c6230/0x2c6334 (RF[13,14])
- ★ S-BOX = SM3 round constants T_j (0x79CC4519×16, 0x7A879D8A×32) — dead code in sponge!
- ★ Sign counter (RF[9]) = 逐 sign call +1 遞增 (v132d: 27 signs 實測確證)
- ★★ HEAD counter ≠ RF[9]! 獨立計數系統, 每 ~4 signs +1
BODY (292B) = raw sponge output, 無 Layer 2/3 (v97: 292/292 byte match)。
HEAD (20B) = SHA1_base[i] ⊕ K[i] ⊕ C[i%4] (v134b: 3 unique HEAD × 20B = 60/60 ✓✓✓):
  SHA1_base = SHA-1(session_4B + "1128" + "\x6e\x8f\x79\x74")  [20B, device constant]
  K = session key [20B], K[0:4]=00000000, K[4:20]=session init 派生
  C = head_counter_u32_LE [4B], per-sign-group +1
  ★ C 可從 HEAD[0:4] ⊕ SHA1[0:4] 直接求得 (因 K[0:4]=0)
  ★ K 可從首個 HEAD 反推, 後續 HEAD 用 K + C 驗證 (cross-sign)
  ★ session_4B/tail_4B = per-aid device constants (aid=1128 vs aid=3019 各有一套)
MAIN model 47/47 pass (v103), full chain 46/46 (v115)。
**KS compound 17/17 slots 全歸因** (v115+v131): 13 closed-form + 5 COPY (h=169, 92/92 verified)。S-BOX = SM3 round constants T_j (dead code)。
**Sponge round = SM4/SM3 風格 ARX+Boolean mixer** (v120)。
## 總判決: ≈99% 理解, ≈95% 可離線復現 (v6: 六元全勝, 真空缺僅 2 項)

殘缺 2 項 (真空缺), 6 項 (已修):
已修 (transcript 溯源 + v134b):
- ✅ HEAD = SHA-1(12B) 非 SM3 — v31m sha1io (2026-04-18) 已解
- ✅ Block C (POST) = MD5(POST body) = X-SS-STUB — v31m v10-v13 已解
- ✅ SM3 pre_state chain = SHA-1(12B)→RC4 KSA(drop=219)→SM3 IV — v31m sha1io 已知
- ✅ HEAD 完整公式 (v134b: 60/60 三重驗證, v6: 28/28 六元全勝)
    HEAD[i] = SHA1_base[i] ⊕ K[i] ⊕ C[i%4]
    K[0:4]=00000000, K[4:20]=device constant, cross-sign 首 HEAD 可反推
    C=head_counter_u32_LE (持久化累計, per-sign-group +1)
- ✅ session_4B/tail_4B = per-aid device constant (trace: aid=1128/3019)
- ✅ K[4:20] 跨 session 恆定 (v5/v6 K[0:8] 一致, device constant)
    離線窮搜全 ✗ (非 RC4/MD5/SHA1/SHA256 of known constants)
    ★ 首 HEAD 反推 K → 一次捕獲永久有效, 派生源不影響實用
- ✅ Block C (GET) = SESSION CONSTANT! (blockc_trace v2: 跨 2 session, 12 signs)
    52B input = session-constant 結構化數據 (非 per-sign hash)
    Block A = 全零 (非 SM3 digest! full_trace 假設已推翻)
    Block C = [heap_ptr_low32, 0x78, heap_ptr_low32, 0x78] (ASLR 依賴)
    52B[48:52] ≠ timestamp (是 session 值, 非 time())
    ★ 首 sign 捕獲 52B → 整 session 有效, 無需 per-sign 計算
    ★ 推翻: full_trace 之 "Block C = per-sign, high entropy, deterministic" 假設
真空缺:
- ★ Sign counter 初始值 = 需 Frida 捕獲/session (HEAD counter 持久化累計)
- ★ M_total 跨 session 恆定性 = 未驗 (理論上 = build-time constant)

---

## 一、已完全解明 (可離線復現)

### 1.1 HEAD 20 bytes — ✅ v134 final (14/14 ✓)

```python
# v134 確證: HEAD = session_HEAD_base ⊕ [counter_lo8, 0, 0, 0]
# session_HEAD_base = SHA-1(12B) ⊕ session_mask(20B)
sha1_input = session_4B + b"1128" + b"\x6e\x8f\x79\x74"   # 12 bytes
sha1_raw = SHA1(sha1_input)                                  # 20 bytes
session_HEAD_base = sha1_raw ^ session_mask                   # 20 bytes, session constant
HEAD[i] = session_HEAD_base[i] ^ [counter_lo8, 0, 0, 0][i % 4]
```

v133: SHA1(12B) hashlib.sha1 驗證 ✅。
v134: session_HEAD_base ≠ SHA1(12B) — 存在 20B session_mask (非 RC4 keystream)。
  bytes at i%4!=0 為 session constant (15B, 跨 sign 恆定, 14/14 ✓)。
  bytes at i%4==0 一致 XOR 變化 (5B, counter_lo8, 14/14 ✓)。
  驗證策略: 首 HEAD 作 reference, 無需 SHA-1 或 session_mask。
session_4B = per-aid device constant (aid="1128" → 0xc9a450ec, aid="3019" → 0x2c481f6e)。
"n\x8fyt" 亦見於 md5#4 input ("1128n\x8fyt1128"), 為 build/app constant。

### 1.2 MID 17 bytes — ✅ v31m 公式已解 (v129: GF(2⁸) affine transform)

v31m 之 MID 結構與舊版完全不同 (非 MD5):
```
MID[0:2]  = PRNG (arc4random() & 0xFFFF, 服務器不驗)
MID[2:3]  = 0x00 (null separator, 恆定)
MID[3:4]  = 0x0d (= 13, MID-E 長度, 恆定)
MID[4:17] = MID-E = GF(2⁸) affine transform of 52B input (20/20 verified)
```

MID-E 計算: `output[32] = M_total[32×52] × input52 + c_total[32]`, 取 `output[19:32]` (13B)。
52B input = `[Block_A 16B][Block_B 16B][Block_C 16B][timestamp 4B]`。
M_total 與 c_total 為 session constants (v31j-v31l 求解, 20/20 驗證通過)。

舊版公式 (v1-v43, 不同 .so): MID[0:16]=MD5(HEAD+BODY), MID[16]=GF checksum — v31m 不適用。

### 1.3 MID-B 2 bytes + Trailer 2 bytes — 100%

```
MID-B = arc4random() & 0xFFFF   (服務器不驗)
Trailer = arc4random() & 0xFFFF  (服務器不驗)
```

### 1.4 BODY 外殼 — 95%

```
[type=0x35] [header 8B] [payload 281B] [trailer 2B]

header[0:4] = random (PRNG[3] LE, 不驗)
header[4]   = 0x01
header[5:7] = sponge output[6:7] (per-sign, v97: BODY=raw sponge)
header[7]   = 0x18
trailer     = random (不驗)
```

### 1.5 Layer 2 — HEAD-only Counter XOR (v97+v98 修正)

**BODY 無 Layer 2** (v97: workspace==a3[37:], 292/292 identical)。
**HEAD 有 per-sign XOR**: `HEAD[i] = session_HEAD_base[i] ^ [counter_lo8, 0, 0, 0][i%4]` (v134, 14/14 ✓)。
session_HEAD_base = SHA-1(12B) ⊕ session_mask(20B), 20B session constant。

### 1.6 Layer 3 — ~~Bit-Packing~~ v31m 中不存在 (v97 修正)

**v97 確證**: a3[37] = 0x35 (type byte) 直接可讀, 兩 sign 皆然。BODY 為 raw sponge output, 無 bit-level permutation。

先前 v92 之「bit7 互補」分析基於不同 session 之數據 (不同 URL → 不同 sponge output), 誤判為 bit permutation。v97 之 workspace==a3[37:] byte-exact match 為最終裁決。

---

## 二、Layer 1 — ARX Sponge Permutation (核心)

### 2.1 整體結構

```
Sponge(URL_query, state[0:31]):
    Setup:   LDB#1 (2 CL, input=0x00)
    Init:    LDB#2 → 138 h0 permutation (init-specific bytecodes)
    Inject:  LDB#3..#22: 20 bytes 純注入 (5B binary header + 15B URL start)
    Main:    [LDB → 83 h0 + 76 CL + 112 ADD] × N  (N = URL_len ÷ ~16)
    Tail:    38 LDBs (state cleanup + propagation + sequential read)
    Output:  BODY (292B) = raw sponge output → a3[37:329] (via RF[6]=a3+37)
             HEAD (20B) = SHA-1(12B session input) XOR [counter&0xFF,0,0,0] → a3[0:20]
             MID (17B) = [PRNG 2B][0x000d][GF(2⁸) affine 13B] → a3[20:37]
             base64_core(a3, 329) → X-Medusa
```

**Init 僅 1 次 permutation** (138 h0, LDB#2), 非 21 次。LDB#3-22 之 20 bytes 被寫入 sponge state 不經 permutation (v77 確證)。

**Absorb 機制 (v73+v76 確證)**: URL data 通過 FRONT 之 COPY/LOAD (RF[14] sliding pointer) 吸入, 每 round 64 bytes。Context buffer = URL query string (v76 ASCII 驗證)。

### 2.2 VM 架構

```
Register File (RF): x23 指向, ≥256 slots × 8 bytes (2KB+)
Entry Table:        x20 指向, entry size = 0x30 (48 bytes)
Handler Table:      x24 指向, handler[index] = code address
Float RF:           x25/x26 指向 (float/S-BOX table)
PC Counter:         x19 指向 (w19 = current bytecode index)
```

VM 為 dispatch-based: 每個 handler 從 entry 讀 bytecode, 執行操作, dispatch 至下一 handler。

### 2.3 Handler 清單 (SO 反彙確證)

| 地址 | 操作 | 活躍 | 確證 |
|------|------|------|------|
| 0x2b102c | XOR: `RF[d] = RF[a] ^ RF[b]` | ✓ 83/round | v44,v57,v64 |
| 0x2b0444 | ADD: `RF[d] = sxtw(RF[a] + RF[b])` | ✓ 95/round (MAIN) | v70,v71 |
| 0x2b3bac | Key Schedule: `bl 0x2c6230` (TABLE_LOOKUP+COPY) + `bl 0x2c6334` (ADD_IMM) | ✓ 48/round | v85,v87,反彙 |
| 0x2b10e4 | COPY/LOAD: `RF[d] = sext32(mem[off+RF[s]])` | ✓ 76/round | v63,v73 |
| 0x2b6b6c | XOR (h3): `RF[d] = RF[a] ^ RF[b]` | ✓ 48/round | v55b |
| 0x2b6ba0 | ROR (h3): `RF[d] = ROR32(RF[s], shift)` | ✓ 48/round | v45 |
| 0x2b6be4 | ROR2 (h3): `RF[d] = ROR32(RF[s], shift)` | ✓ 48/round | v62 |
| 0x2c3cb8 | XOR (h18): `RF[d] = RF[a] ^ RF[b]` | ✓ 48/round | v56 |
| 0x2c3cec | ADD (h18): `RF[d] = RF[a] + RF[b]` | ✓ 48/round (infra) | v54 |
| 0x2b6aec | COPY (h3): `RF[d] = RF[s]` | 23/sign (非 MAIN) | v52c |
| 0x2c3c3c | XOR1 (h18): | 1/sign (非 MAIN) | v52c |
| 0x2c3c78 | ADD1 (h18): | 1/sign (非 MAIN) | v52c |
| 0x2b6a90 | ADD (h3 region): | 0/round (不活躍) | v62 |
| 0x2b6ac4 | OR (h3 region): | 0/round (不活躍) | v62 |
| 0x2c3c14 | ADD0 (h18 region): | 0/round (不活躍) | v62 |

### 2.4 MAIN Permutation — 完整操作序列

每 round 之 MAIN 區段包含 48 triples。每 triple 之 dispatch chain:

```
h3 compound → h0 XOR → h18 compound → ADD@0x2b0404 → (repeat)
```

(COPY/LOAD 不在 MAIN — 僅 FRONT 觸發, v72/v73 確證)

**完整 triple (9 RF writes):**

```python
# ① RF[13,16,17]: 由 0x2b3bac compound handler 更新 (每 triple, between ADD1/ADD2):
#    0x2c6230 Op1: RF[byte1] = sext32(mem[sext16(offset) + RF[byte0]])  (TABLE LOOKUP)
#    0x2c6230 Op2: RF[dest] = RF[src]                                   (COPY)
#    0x2c6334 Op1: RF[byte1] = RF[byte0] + sext16(offset)               (ADD IMMEDIATE)
#    Magic constants (K0..K3) = 純混淆 state machine, 不參與計算!
#    通過 aliased pointer x19+0x6050 = x23 寫入 RF

# ② h3 XOR (0x2b6b6c)
RF[12] = RF[13] ^ RF[12]                        # v55b: RF[13] 每 triple 不同
                                                 # (from TABLE_LOOKUP via 0x2c6230)

# ③ h3 ROR1 (0x2b6ba0)
RF[15] = ROR32(RF[5], 23)                       # v45: 48/48 × 4 rounds

# ④ h3 ROR2 (0x2b6be4)
RF[14] = ROR32(RF[5], 15)                       # v72: src=5, shift=15
                                                 # 47/47, 跨 sign 恆定
                                                 # = ROR32(RF[15], 24) ✓ v50

# ⑤ h0 XOR (0x2b102c)
RF[5] = RF[15] ^ RF[5]                          # v44: bytecode 0x0105050f
                                                 # v58: opA=RF[15]✓ opB=RF[5]✓
                                                 # v64: 48/48 恆定

# ⑥ h18 XOR (0x2c3cb8)
RF[24] = RF[14] ^ RF[5]                         # v56: 10/10 match

# ⑦ h18 ADD (0x2c3cec) — VM infrastructure (非 crypto)
RF[14] = bytecode_base_ptr + PC_counter          # v54: opA 每次 +4

# ⑧ ADD1 (0x2b0444) — 模加混合
RF[5] = sxtw(RF[17] + RF[16])                   # v71: bytecode 0x00051110
                                                 # RF[16,17] 由 TABLE_LOOKUP/COPY/ADD_IMM 產生
                                                 # (0x2c6230+0x2c6334, from entry bytecodes, v87)

# ⑧½ PRNG (0x2b3bac → bl 0x2c6230) — Round Key Generation (v85+v87)
# RF[13], RF[16], RF[17] = PRNG(state)           # 通過 x19+0x6050 (=x23) 寫入
#   magic: 0xb8ede0c2, 0x481882e9, 0x1a9638a5, 0x0ecb0109
#   RF[13] → 下一 triple 之 h3 XOR key
#   RF[16,17] → 下一 triple 之 ADD1 operands

# ⑨ ADD2 (0x2b0444) — 模加累積
RF[5] = sxtw(RF[12] + RF[5])                    # v71: bytecode 0x02050c05
                                                 # 47次/round (最後 triple 省略)
```

### 2.5 FRONT (32 h0 XOR + 16 URL absorb + context init)

v74 確證全部 32 FRONT h0 bytecodes (83/83 跨 sign 恆定):

```python
# ── Context state 載入 (52 CL, round 開始前, v73) ──
for i in range(52):
    RF[13] = sext32( mem[RF[5] + 40 + i*4] )

# ── Propagation 載入 (8 CL, round 開始前, v73) ──
# RF[3,4,11,14,18,21,28,29] = mem[RF[8] + {8,12,...,36}]

# ── FRONT: 16 pairs × 2 h0 XOR, 穿插 URL absorb ──
for i in range(16):
    RF[14] = sext32( mem[RF[14]] )          # URL absorb (CL, 4B/op)
    RF[5]  = RF[12] ^ RF[5]                 # h0 odd:  0x0105050c
    RF[12] = RF[13] ^ RF[4]                 # h0 even: 0x010c040d
```

`RF[4]` = input byte (LDB 注入)。`RF[13]` = context state (CL 每次覆寫, 52 值輪替)。

### 2.6 TAIL (3 h0 XOR)

v74 確證全部 3 TAIL bytecodes (跨 sign 恆定):

```python
RF[11] = RF[4]  ^ RF[11]    # 0x010b0b04, dest=11, XOR with input byte
RF[7]  = RF[3]  ^ RF[7]     # 0x01070703, dest=7
RF[9]  = RF[21] ^ RF[9]     # 0x00090915, dest=9
```

### 2.7 COPY/LOAD 語義 (v73 重新定性)

CL **非 S-BOX**, 而是三類記憶體讀取:

| 類別 | 次數 | 公式 | 語義 |
|------|------|------|------|
| Context init | 52/round | `RF[13] = sext32(mem[RF[5]+40+i*4])` | 208B context state |
| URL absorb | 16/round | `RF[14] = sext32(mem[RF[14]])` | 64B URL data, sliding ptr |
| Propagation | 8/round | `RF[misc] = sext32(mem[RF[8]+N])` | State propagation |

CL bytecodes 跨 sign 恆定 (76/76), values 跨 sign 全不同 (0/76) — 因 URL 和 state 不同。

### 2.8 Round-Boundary 不變量

v53 確證 (14 states × 2 signs):

**ROR 不變量:**
```
RF[5]  = ROR32(RF[3],  17)
RF[12] = ROR32(RF[3],   8)
RF[15] = ROR32(RF[3],  23)   (= ROR32(RF[5], 23-17=6)... 待驗)
RF[28] = ROR32(RF[4],  12)
RF[21] = ROR32(RF[14], 19)
RF[29] = ROR32(RF[23],  9)
```

**等價不變量:**
```
RF[11] == RF[17]
RF[18] == RF[20]
```

**獨立 state 變量 (9 個, 288 bits):**
```
RF[3], RF[4], RF[11], RF[13], RF[14], RF[15], RF[18], RF[22], RF[23]
```

其餘 changing registers 為 ROR/copy propagation 之衍生。

### 2.9 RF[5] 完整生命周期 (per triple)

```
RF[5]_start  (= prev ADD2 result)
  │
  ├─→ ③ ROR1:  RF[15] = ROR32(RF[5], 23)     ← 讀 RF[5]
  ├─→ ⑤ h0 XOR: RF[5]₁ = RF[5] ^ RF[15]      ← 寫 RF[5] (XOR)
  ├─→ ⑥ h18 XOR: RF[24] = RF[14] ^ RF[5]₁    ← 讀 RF[5] (消費 XOR 結果)
  ├─→ ⑧ ADD1:   RF[5]₂ = RF[17] + RF[16]      ← 寫 RF[5] (覆寫!)
  └─→ ⑨ ADD2:   RF[5]₃ = RF[12] + RF[5]₂      ← 寫 RF[5] (最終值)
  
RF[5]_end = RF[12] + RF[17] + RF[16]
```

此解釋了 nilpotent 矛盾: `(I+R²³)^48 = 0` 不適用, 因 ADD1 在每 triple 完全覆寫 XOR 累積。

⚠ **v87+離線反彙 確證**: RF[13,16,17] 在 MAIN 中被 0x2b3bac compound handler 更新 (through aliased pointer x19+0x6050=x23)。0x2c6230 為 TABLE LOOKUP + COPY (with obfuscation state machine), 0x2c6334 為 ADD IMMEDIATE。Magic constants = 純混淆。每 triple 之 ADD1 使用 3 個 bytecode-derived 值, 全部可離線推導。

### 2.10 ARX + Key Schedule 構造確認 (全部 operands 已知)

```
A = Add:      RF[5] = sxtw(RF[17]+RF[16])    (0x2b0444, bytecode 0x00051110)
              RF[5] = sxtw(RF[12]+RF[5])      (0x2b0444, bytecode 0x02050c05)
R = Rotate:   RF[15] = ROR32(RF[5], 23)       (0x2b6ba0)
              RF[14] = ROR32(RF[5], 15)        (0x2b6be4, v72 確定)
X = XOR:      RF[12] = RF[13]^RF[12]          (0x2b6b6c, RF[13]=PRNG per-triple)
              RF[5]  = RF[15]^RF[5]            (0x2b102c, bytecode 0x0105050f)
              RF[24] = RF[14]^RF[5]            (0x2c3cb8)
K = KeySched: RF[13] = TABLE_LOOKUP(entry bytecode)   (0x2c6230, Op1)
              RF[?]  = COPY(entry bytecode)             (0x2c6230, Op2)
              RF[?]  = ADD_IMM(entry bytecode)          (0x2c6334, Op1)
              via aliased pointer x19+0x6050 = x23
              magic constants = 純混淆, 不參與計算!
```

MAIN 為 ARX + Key Schedule 構造: 每 triple 10 個 ops, 含 3 個 key writes (TABLE_LOOKUP + COPY + ADD_IMM)。
全部操作之語義已完全解碼, 可從 entry table bytecodes 離線推導。

### 2.11 Entry Table Bytecodes (v88 完整 dump)

全 48 MAIN triples 之 key schedule entries **完全恆定** (47/47 cross-triple, 10/10 cross-sign)。
此為 **build-time constants**, 可嵌入離線復現程式碼。

```
Key Schedule entries per triple (10 entries after ADD1, from x0):

Entry  w0          w8          Handler  語義
─────────────────────────────────────────────────────────
+0     0xf338c080  0xf338c050  220      0x2c6230 TABLE_LOOKUP+COPY
+1     0x00000e0e  0xf2610083  92       (CL-equiv)
+2     0x00130004  0x4880346f  169      CL: RF[19]=mem[off+RF[4]]
+3     0x001d001c  0x09801074  169      CL: RF[29]=mem[off+RF[28]]
+4     0x00110017  0x0c3ff028  169      CL: RF[17]=mem[off+RF[23]]
+5     0xf338c1a0  0xf338c170  471      0x2c6334 ADD_IMM
+6     0x00150003  0xa2568081  169      CL: RF[21]=mem[off+RF[3]]
+7     0x0004001b  0xea000101  169      CL: RF[4]=mem[off+RF[27]]
+8     0x12050e05  0x087e020a  48       XOR: RF[18]=RF[5]^RF[14]?
+9     0xf338c230  0xf338c200  528      Next compound dispatch
```

---

## 三、VM Dispatch Chain (SO 反彙)

### 3.1 MAIN Triple 之完整 dispatch

```
h3 compound (0x2b6b34):
  ├─ Word 1: h3 XOR  → RF[12] = RF[13]^RF[12]   (STR @ 0x2b6b6c)
  ├─ Word 2: h3 ROR1 → RF[15] = ROR32(RF[5],23)  (STR @ 0x2b6ba0)
  └─ Word 3: h3 ROR2 → RF[14] = ROR32(RF[?],?)   (STR @ 0x2b6be4)
  dispatch (0x2b6be8: br x12) → h0

h0 XOR (0x2b0ff0):
  └─ RF[5] = RF[15] ^ RF[5]                       (STR @ 0x2b102c)
  dispatch (0x2b1030: br x12) → h18

h18 compound (0x2c3c80):
  ├─ Part 2 XOR: RF[24] = RF[14]^RF[5]            (STR @ 0x2c3cb8)
  └─ Part 2 ADD: RF[14] = base+PC                  (STR @ 0x2c3cec)
  dispatch (0x2c3cf0: br x11) → ADD@0x2b0404

ADD handler (0x2b0404) — ADD1:
  └─ RF[5] = sxtw(RF[17]+RF[16])                  (STR @ 0x2b0444)
  dispatch → 0x2b3bac

ADD handler (0x2b0404) — ADD1:
  └─ RF[5] = sxtw(RF[17]+RF[16])                  (STR @ 0x2b0444)
  dispatch → 0x2b3bac

**Key Schedule handler (0x2b3bac)** — RF[13,16,17] writer (v85+v87+反彙):
  ├─ bl 0x2c6230: TABLE_LOOKUP (RF[byte1] = sext32(mem[off+RF[byte0]])) + COPY (RF[dest]=RF[src])
  └─ dispatch → 0x2b3bd4:
  ├─ bl 0x2c6334: ADD_IMM (RF[byte1] = RF[byte0] + sext16(offset))
  └─ dispatch → ADD handler (0x2b0404) — ADD2
  (0x2c6230/0x2c6334 通過 x12=x19+0x6050=x23 寫 RF, magic constants = 純混淆)

ADD handler (0x2b0404) — ADD2:
  └─ RF[5] = sxtw(RF[12]+RF[5])                   (STR @ 0x2b0444)
  dispatch → h3 compound (next triple)

(COPY/LOAD 不在 MAIN — 僅 FRONT 觸發, v72 確證)

h3 compound (next triple)...
```

### 3.2 Handler 地址空間

```
0x2b0000 - 0x2b1300: h0 region (XOR, ADD@0x2b0404, CL, SUB)
0x2b6a00 - 0x2b6e00: h3 region (XOR, ROR×2, CPY, ADD, OR)
0x2bf500 - 0x2bf700: compound ADD+ROR+ROR (FRONT/TAIL only)
0x2c3b80 - 0x2c3d80: h18 region (XOR, ADD, CPY, XOR1, ADD1)
```

---

## 四、確證矩陣

| 操作 | 確證實驗 | 數據量 | 跨 sign |
|------|---------|--------|---------|
| h0 XOR dest=RF[5] (MAIN) | v57 | 83/83 | 2/2 ✓ |
| h0 XOR bytecode=0x0105050f | v64 | 48/48 | 2/2 ✓ |
| h0 XOR opA=RF[15], opB=RF[5] | v58 | 4/4 | 2/2 ✓ |
| h3 XOR: RF[12]=RF[13]^RF[12] | v55b | 2/2 | 2/2 ✓ |
| h3 ROR1: RF[15]=ROR32(RF[5],23) | v45 | 48×4 | 2/2 ✓ |
| h3 ROR2: dest=RF[14] | v62 | 48/48 | 2/2 ✓ |
| h18 XOR: RF[24]=RF[14]^RF[5] | v56 | 10/10 | 2/2 ✓ |
| h18 ADD: infra (base+PC) | v54 | 48/48 | 2/2 ✓ |
| ADD1: RF[5]=sxtw(RF[17]+RF[16]) | v71 | 48/48 | 2/2 ✓ |
| ADD2: RF[5]=sxtw(RF[12]+RF[5]) | v71 | 47/47 | 2/2 ✓ |
| CL: dest RF[13]×52, RF[14]×17 | v63 | 76/76 | 2/2 ✓ |
| h3 ROR2: RF[14]=ROR32(RF[5],15) | v72 | 47/47 | 2/2 ✓ |
| CL: MAIN 中不觸發 (RF[13] 由 key schedule 更新) | v72,v83,v87 | CL=0, KS=48 | ✓ |
| CL: 非 S-BOX, 3 組 (context/URL/prop) | v73 | 76/76 bytecodes | 2/2 ✓ |
| CL: RF[14] 值 = URL ASCII | v73 | 直接 ASCII 驗證 | 2/2 ✓ |
| Context buffer = URL query string | v76 | ASCII decode 確證 | 2/2 ✓ |
| RF[5] at CL time = valid pointer | v76 | 3/3 dumps | 2/2 ✓ |
| RF[11]=0xd0=208=context size | v76 | 2/2 signs | 2/2 ✓ |
| Context buffer 跨 sign 相同 (round1) | v76 | byte-level 比較 | 2/2 ✓ |
| Init: 1 permutation (138 h0) + 20 byte loads | v77 | h0/CL/ADD 計數 | 2/2 ✓ |
| Init: h0/CL/ADD 結構跨 sign 完全恆定 | v77 | 25/25 sub-rounds | 2/2 ✓ |
| Init: 5 binary header bytes 跨 sign 恆定 | v77 | 5/5 identical | 2/2 ✓ |
| Init permutation: 138 h0, 4 bytecodes, 跨 sign 恆定 | v78 | 138/138 | 2/2 ✓ |
| Init RF[12,13,16,17]=0 at init END | v78 | 2/2 signs | 2/2 ✓ |
| Init RF[9] = sign counter (+5/sign) | v78 | 0x...1d vs 0x...22 | 2/2 ✓ |
| STB fires ~3100 times per sign (global) | v80 | 3109/3247 | 2/2 ✓ |
| base64_core a3 = 329B encrypted BODY | v81 | hex dump | 2/2 ✓ |
| a3[0:20] 跨 sign 恆定 (=HEAD) | v81 | 20/20 bytes | 2/2 ✓ |
| Squeeze: 無 329-byte LDB 循環 (僅 20-38 tail) | v82 | LDB 計數 | 2/2 ✓ |
| Output = state buffer 直讀 (base64_core a3=ptr) | v82 | pipeline 分析 | 2/2 ✓ |
| Sponge LDB total ≈ URL_len + 60 (非 ×2) | v82 | 2392 vs 2447 | 2/2 ✓ |
| MAIN ROR 不變量: r[15]=ROR(r[5],23), r[14]=ROR(r[5],15) | v83 | MAIN_END | 2/2 ✓ |
| MAIN 等價: r[3]==r[24] | v83 | MAIN_END | 2/2 ✓ |
| ⚠ RF[13] 在 MAIN 中變化 (CL=0, 0x2b19d8=0) | v83,v84 | Δ≠0 | 2/2 ⚠ |
| ADD1 dispatch → 0x2b3bac (48×), ADD2 → 0x2b6b34 (47×) | v85 | 95/95 | 2/2 ✓ |
| 0x2b3bac = RF[13] PRNG writer (bl 0x2c6230) | v85 | RF[13] 每 triple 變 | 2/2 ✓ |
| ★ x19+0x6050 == x23 (aliased pointer) | v87 | eq=True | 2/2 ✓ |
| PRNG 同時寫 RF[13,16,17] (47/94 sync changes) | v87 | 47/94 each | 2/2 ✓ |
| PRNG 為 Round Key Generator (3 keys/triple) | v87 | data pattern | 2/2 ✓ |
| 0x2c6230 = TABLE_LOOKUP+COPY (非 PRNG!) | 離線反彙 | 逐指令解碼 | ✓ |
| 0x2c6334 = ADD_IMMEDIATE (非 hash!) | 離線反彙 | 逐指令解碼 | ✓ |
| Magic constants (K0..K3) = 混淆, 不參與計算 | 離線反彙 | 恆定路徑 | ✓ |
| Entry table 48 triples 完全恆定 | v88 | 47/47 identical | 2/2 ✓ |
| Entry table 跨 sign 完全恆定 | v88 | 10/10 identical | 2/2 ✓ |
| Entry table = build-time constant (可嵌入程式碼) | v88 | 96/96 | ✓ |
| a3 buffer NOT within RF (separate, diff=2.5GB) | v89 | overlap=False | 2/2 ✓ |
| HEAD per-sign byte[0] Δ = counter_lo8 diff | v98 | 4/4 signs × 5/5 pos | ✓ |
| HEAD = SM3 XOR [counter&0xFF, 0, 0, 0] | v98 | 20/20 bytes constant | ✓ |
| ~~Layer 3 bit permutation~~ 不存在 (v97 推翻 v92) | v97 | 292/292 match | 2/2 ✓ |
| RF[6] = a3 + 37 (pointer into buffer) | v89 | offset 恆定 | 2/2 ✓ |
| STB (0x2b1930) 不寫 output buffer a3 | v90 | x8=RF idx not addr | 2/2 ✓ |
| 329B = HEAD(20) + MID(17) + BODY(292) | v89+v90 | RF[6]=a3+37, a3[37]=0x35 | 2/2 ✓ |
| ★★★★★ BODY = raw sponge output (ws==a3[37:], 無 Layer 2/3) | v97 | 292/292 identical | 2/2 ✓ |
| x19+0x40 == a3+37 == RF[6] (workspace pointer = BODY) | v97 | pointer match | 2/2 ✓ |
| BODY 由 post-sponge native copy 寫入 (非 STB) | v90+v91+v93 | 4 輪 0 matches | ✓ |
| STB 0x2b1930 僅做 sponge RF 內部操作 | v93 | base ≠ a3 | ✓ |
| Sponge state buffer = VM struct (非 output) | v94 | XOR random | ✓ |
| Output 329B 由 native code 組裝 (sign epilogue) | v94 | pipeline 確證 | ✓ |
| h0 FRONT: [RF[5]=RF[12]^RF[5], RF[12]=RF[13]^RF[4]] ×16 | v74 | 32/32 | 2/2 ✓ |
| h0 TAIL: RF[11]=RF[4]^RF[11], RF[7]=RF[3]^RF[7], RF[9]=RF[21]^RF[9] | v74 | 3/3 | 2/2 ✓ |
| h0 全 83 bytecodes 跨 sign 恆定 | v74 | 83/83 | 2/2 ✓ |
| x23 IS sponge RF | v51 | sample#0 完美 | 2/2 ✓ |
| RF[5] 被 ADD@0x2b0444 修改 | v70 | 95/95 | 3/3 ✓ |
| RF[5] carry=0 (h0 間必變) | v66 | 0/5 | 2/2 ✓ |
| RF[5] 寫入在 h18→h3 窗口 | v67 | 40/40 | 2/2 ✓ |
| ROR 不變量 (6 組) | v53 | 14 states | 2/2 ✓ |
| 等價不變量 r[11]==r[17] | v53 | 14/14 | 2/2 ✓ |

---

## 五、殘留缺口

### 缺口 1 ★★ State 初始值 (大部已解, v75+v76+v78)

v76 確證 context buffer = **URL query string** (ASCII), 跨 sign 完全相同。

**已知 (v75+v76):**
- RF[5] at CL time = pointer to URL/context buffer (0x783cfed8d0)
- Buffer[0:64] = URL query params: `aweme_id=7631902...&cursor=0&count=20&address_book_acce`
- 每 round 消費 64B (16 CL × 4B), RF[5] 不變 (CL 之 offset 遞增)
- RF[11] = 0xd0 = 208 = 52×4 → context size 參數
- RF[22] = RF[24] = URL total length (2447/2784, per-sign 不同)
- RF[16]=0, RF[17]=0 at main_round1_start (ADD source 初始值)
- Init 消耗 ~21 LDB, 切換 x23 base
- RF[12,13] 跨 sign 不同 → init phase 注入 session 隨機性 (RF[7] timestamp, RF[9] counter)
- T3 (round1 後) 跨 sign 完全相同 → 同 URL 確定性

**未知:**
- RF[6] = pointer to SM3 T_j round constants table (build-time, 48 entries: 0x79CC4519×16 + 0x7A879D8A×32, dead code in sponge rounds). ★ POINTER VALUE 本身被 Init phase 用作 crypto seed (RF[5]=RF[6]^RF[9]), per-session 不同 (ASLR), 需 1 次捕獲/session。
- RF[9] counter 初始值: 需 Frida 捕獲/session (遞增 +1/call, v132d 確證; 初始值公式未識)

### 缺口 2a ~~★★★ 0x2c6230 PRNG 演算法 + Entry Bytecodes~~ ✅ 完全解碼 (v85+v87+v88+離線反彙)

v88 確證 entry table bytecodes = **build-time constants** (48 triples 恆定, 跨 sign 恆定)。
10 entries per triple, 全部 w0/w8/handler 值已 dump (見 §2.11)。

**0x2c6230 / 0x2c6334 非 PRNG!** 而是 VM bytecode handlers, 附帶混淆 state machine。

**0x2c6230** (65 指令 → 2 ops):

```python
# State machine (K0=0xb8ede0c2, K1=0x0ecb0109, K2=0x481882e9, K3=0x1a9638a5)
# 永遠走同一路徑 → 純混淆, 不參與計算!

# Op1: TABLE LOOKUP (from entry[0x08] bytecode)
bytecode1 = *entry[0x08]
byte0 = bytecode1 & 0xFF         # source RF index
byte1 = (bytecode1 >> 8) & 0xFF  # dest RF index
offset = sext16(bytecode1 >> 16) # signed 16-bit offset
RF[byte1] = sext32( mem[offset + RF[byte0]] )

# Op2: COPY (from entry[0x00] bytecode)
bytecode2 = *entry[0x00]
src = bytecode2 & 0xFF
dest = (bytecode2 >> 16) & 0xFF
RF[dest] = RF[src]

# PC += 3
```

**0x2c6334** (36 指令 → 1 op):

```python
# State machine (K0'=0xa80f34f3, K1'=0x0dae3396, K2'=0xf4ccba57, K3'=0x4833ce60)
# 同樣純混淆!

# Op1: ADD IMMEDIATE
RF[byte1] = RF[byte0] + sext16(bytecode >> 16)

# PC += 3
```

**0x2b3bac compound 之完整效果 (per triple):**

```
bl 0x2c6230: RF[?] = TABLE_LOOKUP + RF[?] = COPY    → 寫 RF[13] + RF[16 or 17]
dispatch → 0x2b3bd4:
bl 0x2c6334: RF[?] = ADD_IMMEDIATE                  → 寫 RF[17 or 16]
dispatch → ADD2 (0x2b0444)
```

全部操作可從 entry table bytecodes 離線推導。Magic constants = 純混淆。

### 缺口 2b ~~★★ Output Squeeze + State Buffer Layout~~ ✅ 已解 (v79-v82, v89-v94)

v89-v94 確證 output pipeline:

- **a3 = SEPARATE buffer** (非 RF 區域內, diff = 2.5GB, overlap=False)
- **STB (0x2b1930) 不寫 a3** (v90/v91/v93: 4 輪實驗, 全部 0 matches, definitive)
- **STB x8 = signed offset, x9 = RF[byte0] (sponge internal base)** (v91 修正 v90)
- **sponge state buffer = VM struct** (v94: stateBase 內容為 pointers/counters, 非 crypto output)
- **329B 由 post-sponge NATIVE CODE 組裝寫入** (非 VM handler, 在 sign epilogue 中)
- **RF[6] = a3 + 37** (pointer to BODY start, 兩 sign offset 恆定)
- **RF[20] = a3 + 24** (pointer to MID region)
- **RF at base64_core time = post-sponge infrastructure** (大量 0, sponge state 已清理)

329B layout: `[HEAD 20B (SM3)] [MID 17B (MD5+checksum)] [BODY 292B (sponge output)]`。

**Output pipeline:**
```
Sponge VM (RF[0:255] 累積 crypto state)
  → VM exit
  → Native code: 讀 RF state → 組裝 329B (HEAD+MID+BODY) → 寫 a3
  → base64_core(a3, 329) → X-Medusa
```

**已知:**
- Sponge LDB total = ~2392 (init 22 + absorb ~2332 + tail ~38), v82 確證
- 329B output = base64_core 之 a3 指標直接指向 sponge state buffer
- Tail phase (最後 38 LDBs): 3 子階段 — state 清理 (12 LDB, RF[9,8,7] cycle) + propagation 回寫 (6 LDB, RF[6..10] from RF[21]) + sequential read (19 LDB, `RF[18]=mem[0+RF[10]]`) + 終止 (1 LDB)
- STB = ~1356 (before base64, v82) → sponge 內部 state 寫入, 非 output 寫入
- a3[0:20] 跨 sign 恆定 = session header; a3[20:] = per-sign encrypted payload

**Output pipeline:**
```
Sponge main rounds → state buffer (329B)
  → [tail 處理: cleanup + propagation + sequential read]
  → base64_core(a3 = state_buffer, len = 329)
  → base64 → X-Medusa
```

**未知:**
- State buffer 中 329 bytes 之精確 layout (哪些 RF registers 對應哪些 output 位置)
- Tail sequential read (RF[18]=mem[0+RF[10]] ×19) 之精確作用

### 缺口 3 ~~★★★ h3 ROR2 之 source + shift~~ ✅ 已解 (v72)

`RF[14] = ROR32(RF[5], 15)` — 47/47, 跨 sign 恆定。

### 缺口 4 ~~★★★ S-BOX Table 內容~~ ✅ 已解 (v73) — 非 S-BOX

COPY/LOAD 非 S-BOX, 而是三組記憶體讀取 (v73, 76/76 bytecodes 跨 sign 恆定):

**Group A** (52 ops, h0#0 前): `RF[13] = sext32(mem[40 + RF[5]])` — 一次性載入 208B context state。RF[5] 為 context buffer pointer, offset=40 跳過 header。此值在 MAIN 中作為 round constant。

**Group B** (16 ops, h0#0/2/4/.../30): `RF[14] = sext32(mem[0 + RF[14]])` — URL 資料吸入, 每 round 64B。RF[14] 為 sliding pointer, 穿插於 FRONT h0 XOR 中。值為 URL query string 之 ASCII (確證: "shrink=64_64&aweme_author=...")。

**Group C** (8 ops, h0#0 後): `RF[{3,4,11,14,18,21,28,29}] = sext32(mem[N + RF[8]])` — propagation state 載入。RF[8] 為 state table pointer, offsets = 8,12,16,...,36。

### 缺口 5 ~~★★ FRONT h0 XOR 之精確 source operands~~ ✅ 已解 (v74)

FRONT 32 h0 bytecodes 交替恆定 (83/83 跨 sign):
odd: `0x0105050c` → `RF[5] = RF[12] ^ RF[5]`
even: `0x010c040d` → `RF[12] = RF[13] ^ RF[4]`
TAIL 3 h0 bytecodes 亦完全確定。

### 缺口 6 ~~★★ Init Round~~ ✅ 完全確定 (v77+v78)

v78 確證全部 138 init h0 bytecodes (138/138 跨 sign 恆定, 僅 4 unique):

```python
# Init permutation (138 h0 XOR, LDB#2)
RF[5]  = RF[6] ^ RF[9]                # h0#1: seed (RF[9] = session counter)
RF[9]  = RF[6] ^ RF[21]               # h0#2: secondary seed
for _ in range(68):                    # h0#3-138: diffusion chain
    RF[11] = RF[11] ^ RF[5]           # 0x000b050b
    RF[6]  = RF[11] ^ RF[5]           # 0x0006050b
```

Init inputs: RF[5]=0x1ff, RF[6]=session const, RF[9]=sign counter (+5/sign), RF[11]=0x2710。
Init outputs: RF[5,6,11]=crypto (跨 sign 不同因 RF[9]), RF[12,13,16,17]=0。
x23 在 init 期間切換 (staging → sponge RF)。

v77 確證 init phase 結構: 1 permutation (138 h0) + 20 bytes 純注入 (5B binary header + 15B URL)。

### 缺口 7 ~~★ header[5:7] 來源~~ ✅ 已解 (v97 推翻舊假設)

原始缺口基於舊假設: BODY header 為獨立構造 (非 sponge output)。v97 確證 BODY = raw sponge output → header[5:7] = BODY[6:8] = sponge output stream 之第 6-7 bytes, 由 ARX sponge permutation 決定, 非獨立來源。缺口消失。

### 缺口 8 ~~★★ Native 329B 組裝 Code~~ ✅ 大部已解 (v97)

v97 確證 BODY (292B) = sponge 直接寫入 a3[37:329] (via RF[6] pointer)。無 Layer 2/3 後處理。
Native code 只負責 HEAD (20B SM3) 和 MID (17B MD5+checksum) 之填入 a3[0:37]。HEAD/MID 之離線復現已在 v1-v43 中完成 (SM3 + MD5 + GF checksum)。

---

## 六、關鍵教訓 (v44-v71 歷程)

1. **VM handler 並非只有 h0/h3/h18**: ADD@0x2b0404 為獨立 handler, 不在任何已知 compound 中, 但為 sponge 之核心。

2. **bytecode 讀取源差異**: h0 從 `[x0]` (entry offset 0) 直接讀; h3/h18 從 `[entry[0x10]]` (pointer indirect) 讀。在 STR 時讀 `[x0]` 需修正 entry offset (`x0 - 0x30`)。

3. **數學矛盾是最強之驗證工具**: `(I+R²³)^32 = 0` 之 nilpotent 性質直接證明了隱藏操作之存在, 引導了 v59-v71 之排除式搜索。

4. **SO 全域搜索不可替代**: 128KB handler region 含 1342 個 STR-to-x23, 人工逐一分析不現實, 但 binary scan + capstone 反彙可系統化覆蓋。

5. **MemoryAccessMonitor 有誤報**: v67 之 MAM hit (PC=0x7931e00034) 可能是 Frida trampoline 或 page-fault handler 之偽象; v68 之 dispatch 追蹤更可靠。

6. **「S-BOX」假設之教訓**: v63 發現 COPY/LOAD 76 次/round, 直覺認為是 S-BOX。v73 證明其實為 context state 載入 + URL data 吸入 + propagation, 全部為記憶體讀取, 非密碼學替換表。假設須以數據驗證, 非以直覺命名。

7. **RF[13] 與 RF[5] 之平行**: v83 發現 RF[13] 在 MAIN 中變化, 但 CL=0 且全部已知 RF_WRITE 已排除 — 與 v59-v70 之 RF[5] 問題完全同型。RF[5] 之解為 ADD@0x2b0404 (dispatch chain 中之隱藏 handler)。RF[13] 之解亦然: dispatch chain 中之 PRNG handler (0x2b3bac→0x2c6230)。

8. **Aliased pointer 陷阱 (x19+0x6050=x23)**: v87 確證 0x2c6230 通過 x12=x19+0x6050 寫入 sponge RF, 而 x19+0x6050==x23。全部 x23-based Interceptor hook 完全漏網。此為 .so 級 anti-RE 技巧: 同一記憶體用不同 register 存取, 令 Frida hook 失效。解法: 在安全之已知 hook 點 (如 ADD@0x2b0444) 讀記憶體 diff, 繞過 aliased pointer 問題。

9. **混淆 state machine 之識別**: 0x2c6230 含 4 magic constants (K0..K3) 構成之分支迷宮, 看似 PRNG/hash。離線反彙證明: state machine 永遠走同一路徑, K 值不參與計算, 實際操作僅 TABLE LOOKUP + COPY (2 ops, 5 行核心代碼)。65 條指令中 ~50 條為混淆。教訓: 控制流圖分析 + 常數傳播可消除此類混淆, 不需動態追蹤。

10. **STB ≠ output 寫入** (v90-v94): 4 輪實驗反覆確認 STB (0x2b1930) 之 `strb w10,[x8,x9]` 僅做 sponge **內部** RF 操作 (x9=RF index base, 非 output address)。329B output 由 post-sponge native code 在 sign epilogue 中組裝。此為 VM→native 之邊界問題: VM handler 負責 crypto 計算, native code 負責 output 組裝, 兩者用不同機制寫入不同記憶體區域。教訓: 不可假設 VM 之 store handler 即為 output 寫入點; 需追蹤 VM exit 後之 native code。

11. **Byte-exact match 推翻 bit-level 推論** (v97): v92 基於 known-plaintext 之 bit-level 分析「確證」Layer 3 bit permutation 存在。v97 直接 dump workspace 和 a3 → **292/292 byte-for-byte identical** → Layer 2/3 在 v31m 中不存在。教訓: 間接推理 (bit 模式比對) 可被直接觀測 (byte dump 比對) 推翻。當直接觀測可行時, 永遠優先使用, 即使間接推理看似確鑿。v92 之「bit7 互補」源自不同 URL → 不同 sponge output, 非 bit permutation。

---

## 七、實驗索引

| 版本 | 目的 | 關鍵結果 |
|------|------|---------|
| v44 | bytecode word 提取 | h0 bytecode 正確, h3/h18 讀錯源 |
| v45 | h3 ROR + h18 ADD operands | ROR shift=23 ✓, ADD=infra |
| v46 | 三時點 state dump | session/init/per-URL 區分 |
| v50 | mid-round RF dump | rotation orbit 結構發現 |
| v51 | x23 校驗 | x23 IS sponge RF ✓ |
| v52c | 隱藏 ops 計數 | h3.CPY=23, h18.XOR1=1, h18.ADD1=1 |
| v53 | round-boundary state | 6 ROR + 2 等價不變量 |
| v54 | h3X/h18X/h18A operands | h18 ADD = infra |
| v55b | h3X source 辨識 | RF[12]=RF[13]^RF[12] ✓ |
| v56 | h18X source 辨識 | RF[24]=RF[14]^RF[5] ✓ |
| v57 | h0 全 dest trace | [5,12]×16+[5]×48+[11,7,9] |
| v58 | 256-slot RF dump | opA=RF[15], opB=RF[5] ✓ |
| v59 | h3/h18 STR dest | 全恆定, 排除 RF[5] writer |
| v60 | RF[5] 時間線 | 8A→3X 窗口 EVERY triple 變化 |
| v61 | SO handler 反彙 | 15 RF_WRITE, 8 未 hook |
| v62 | 4 hidden RF_WRITE | ROR2→RF[14], ADD/OR/A0=0次 |
| v63 | CL + SUB | CL 76次, RF[13]×52; SUB 0次 |
| v64 | 48 MAIN h0 bytecode | 全部 0x0105050f (48/48) |
| v65 | float→int handlers | 0次 (不在 sponge) |
| v66 | x10 vs mem[x23+40] | match✓, write✓, carry✗ |
| v67 | MAM + dispatch timeline | 18x→3x 每次變, MAM hit 在 .so 外 |
| v68 | h18 ADD dispatch target | 全部 → 0x2b0404 (IN-LIB) |
| v69 | ADD@0x2b0404 dest (FRONT) | RF[5]×4, RF[23]×16 |
| v70 | ADD@0x2b0404 dest (MAIN) | ★ RF[5] 95/95 (100%) |
| v71 | ADD bytecodes | ★ RF[5]=RF[17]+RF[16], RF[5]=RF[12]+RF[5] |
| v72 | ROR2 src/shift + CL gate | ★ RF[14]=ROR32(RF[5],15); CL MAIN=0 |
| v73 | CL operands + table dump | ★ CL非S-BOX: context init+URL absorb+propagation |
| v74 | ALL 83 h0 bytecodes | ★ FRONT/MAIN/TAIL 全 bytecodes 確定 (83/83) |
| v75 | State Init 3-point dump | x23 切換, RF[5]=0x1ff@T1, init~21 LDB |
| v76 | CL-time dump (RF[5]=ptr) | ★ Context=URL query! RF[11]=208, RF[22]=URL_len |
| v77 | Init round structure | ★ 1 init perm (138 h0) + 20 byte loads, 5 binary header |
| v78 | Init permutation bytecodes | ★ 4 unique bytecodes, XOR diffusion from RF[6,9] |
| v79 | Squeeze STB capture (first 200 LDB) | STB=0 in first 200 → squeeze is later |
| v80 | STB global + base64_core args | ★ STB=3100+! a0/a1=NULL, a3=output ptr |
| v81 | base64_core a3 dump + STB bytes | ★ a3=329B encrypted BODY, a3[0:20]=HEAD (恆定) |
| v82 | Squeeze byte-level (ring buffer) | ★ 無 squeeze 循環: output=state buffer 直讀 |
| v83 | MAIN-only 驗算 (h0#32→h0#80) | 12/32: ROR ✓ 但 RF[13] 隱藏寫入 |
| v84 | 0x2b19d8 (ldrsb+str) hook | 0 ops — 排除此 handler |
| v85 | ADD dispatch target + RF[13] | ★ 0x2b3bac→bl 0x2c6230 = RF[13] PRNG writer |
| v86 | 0x2b3bac Entry C compound | 0 ops — Entry C 不在 MAIN (dispatch 不去) |
| v87 | RF[13,16,17] at ADD + x19+0x6050 | ★★★ x19+0x6050==x23! PRNG 寫 RF[13,16,17] 三者同步 |
| v88 | Entry table bytecodes dump | ★★★★★ 全 48 triples 恆定, 跨 sign 恆定 (build-time constant) |
| v89 | State buffer layout (RF vs a3) | ★ a3 非 RF 內, Layer 2 XOR 覆蓋全 329B |
| v90 | STB output write sequence | STB 不寫 a3 (x8=offset, x9=RF base) |
| v91 | STB corrected (x9=base filter) | output=0, RF[6]≠a3+37 during sponge |
| v92 | Sponge state vs a3 BODY | ★★★ Layer 3 bit permutation 確證! |
| v93 | STB 2000-ring + a3 filter | 0 matches (definitive: STB 不寫 a3, 4 輪確證) |
| v94 | Sponge state buffer vs a3 XOR | state=VM struct (non-output), native code 組裝 329B |
| v95 | base64_core caller backtrace | LR=0x25c080, call site=0x25c07c |
| v96 | x19 struct dump at base64_core | ★ sign counter@+0x28, BODY_len@+0x38, workspace@+0x40, crypto16@+0x48 |
| v97 | a3 vs workspace XOR | ★★★★★ a3[37:329]==ws[0:292] IDENTICAL! BODY=raw sponge, 無 Layer 2/3! |
| v98 | HEAD evolution 4 signs | ★★★★★ HEAD[i]^counter_lo8=CONSTANT! mask=[counter&0xFF,0,0,0] |
| v99 | MAIN+KS end-to-end | 12/32 WITH KS (= same as WITHOUT!) FRONT_END≠MAIN start |
| v100 | MAIN single-triple | 0/47! RF[14]=h18 infra(+4/triple). Model missing ops |
| v101 | Complete triple entry dump | ★ 30 entries decoded: KS has entry[8](h=48)+entry[1](h=92) |
| v102 | Entry[8] RF[5] isolation | Bug: JS parseInt precision. r5_at_ADD2 (memory) correct |
| v103 | All-memory single-triple | ★★★★★ 47/47 PASS (with ADD2.r12)! RF[12] modified in KS! |
| v104 | Full 32-RF KS diff | 17 slots changed: 7 COPY + 2 counter + 3 lookup + 3 hidden + 2 aliased |
| v105 | Extended RF[0:127] dump | ★ Ext RF[32:127] = 0 changes (session constants). RF[128:255] needed |
| v106 | Full RF[0:255] dump | ★★★ RF[32:255]=0 changes! ROL formulas: RF[28]=ROL(RF[13],20), RF[20]=ROL(RF[28],9), RF[22]=ROL(RF[3],19). 14/17 KS 公式破解 |
| v107 | Handler table dump | h=92→0x2b10ac (CL), h=528→0x2bd644. All handler addresses confirmed |
| v108 | Hook h=92 (entry[1]) | 0/47 triggers! Entry[1] consumed by 0x2c6230 (PC+=3), not dispatched |
| v109 | Hook h=169 (post-0x2c6230) | ★★★★★ 0x2c6230 只改 RF[14]! RF[5,12,13,16] UNCHANGED |
| v110 | Hook 3rd ADD per h0 | Entry[8] 不觸發 0x2b0444! h=471→0x2ca0d8 (非 0x2c6334) |
| v111 | Hook 0x2ca0d8 entry | 5 RF change CA→ADD2. Entry bytecodes: e6=0x00150003, e7=0x0004001b, e8=0x12050e05 |
| v112b | 0x2ca0d8 onEnter/onLeave | ★★★★★ 0x2ca0d8 只改 RF[4,5,21]! (NOT RF[12,13,14,16]!) |
| v113 | 0x2cadf4 onEnter/onLeave | 0x2cadf4 只改 RF[5,28]. RF[28]=RF[5]_new. h=528→bl 0x2cadf4 |
| v114 | All compounds + h169 count | ★★★★★ KS = 恆定 6-call 序列: CL6230→h169→h169→CA0d8→CAdf4→h169 (48/48) |
| v115 | 4-point transition snapshot | ★★★★★ KS 17/17 COMPLETE: 13 formulas + 4 S-BOX. RF[13]=ROL(RF[5],12) NEW! |
| v116 | PC step + entry bytecodes | PC 430→409 (backwards!). 20 entries in [371→409] path. Entry table dumped |
| v117 | S-BOX dump via RF[1] | ★★★★★ S-BOX = SESSION CONSTANTS! RF[1] constant, S-BOX per-sign different |
| v118 | Handler table + bl targets | h=423,461 = inline handlers (no bl). All compound addresses mapped |
| v119b | Full entry table 370-450 | ★★★ Entry[430] h=163 BRANCH w0=-59 → jumps to [371]. 39-entry ARX mixing network |
| v120 | All-handler onEnter trace | ★★★★★ 38/38 sponge round operations ALL DECODED! 20 handlers × 48 rounds. SM4/SM3 ARX+Boolean mixer |
| v121 | All 47 rounds init+final RF | ★★★★★ Offline Simulator: 46/46 × 2 signs = 1932 RF computations PASS! |
| v122 | CL memory region dump | RF[9]=rate buffer (URL context!), RF[6]=S-BOX constants. S10.1=rate read confirmed |
| v123 | Extended RF[0:127] dump | 128-slot formula search for S4.0 → NO MATCH |
| v124 | Full RF[0:255] dump | ★★★ 256-slot exhaustive (4.3M formulas) → S4.0 = MEMORY READ confirmed. Not in RF at all |
| v125 | h=610 handler + 20 handler addresses | h=610=INLINE ADD+ORR (no bl, no memory read). Complete handler table |
| v126 | Handler table h=88..100 | h=96≠h=92 (no alias). All unique addresses confirmed |
| v127 | h=96 bytecodes capture | ★★★ h=96 NEVER writes RF[16]! dest=RF[22,20,12] only |
| v128 | h=105 bytecodes + entry table | ★★★★★ RF[16]=MAJ(RF[29],RF[20],RF[28]) — 92/92 verified! Entry[383]+[392] two-write pattern. SM3 majority primitive |
| v129 | MID 公式 cross-reference | ★★★ MID (17B) 已解: [PRNG 2B][0x000d][GF(2⁸) 13B]. 非 MD5. v31m 用 affine transform 取代. 20/20 MID-E verified |
| v130 | URL absorption rate buffer dump | ★★★★★ Rate buffer = sponge STATE BUFFER (256B). RF[9]+0x00..0x3F = raw URL tail (64/64 match!). RF[9]+0x44+ = absorbed state. URL absorption = standard sponge XOR+permute in 64B blocks |
| v131 | KS S-BOX + h=169 disasm + cross-sign verify | ★★★★★ h=169=COPY (92/92 verified). S-BOX=SM3 round constants T_j (48/48). Dead code: rf[13]=rf[6]+rf[19] overwritten before use. NO session init needed! |
| v132 | Sign counter increment (RF[9] at Init h0 via x23) | ★★★★★ RF[9] = SESSION CONSTANT (7/8 Medusa signs identical). 非 per-sign 遞增! 每 session 捕獲 1 次即可。Audit = 100% |
| v107 | Handler table dump | h=92→0x2b10ac. ★ h=92 = standard CL handler |
| v108 | Hook h=92 intermediate | 0/47 triggers! Entry[1] consumed by 0x2c6230 (PC+=3) |
| v109 | Hook h=169 intermediate | ★★★★★ 0x2c6230 only changes RF[14]! RF[5,12,13,16] unchanged. Entry[8] ADD verified 47/47 |
