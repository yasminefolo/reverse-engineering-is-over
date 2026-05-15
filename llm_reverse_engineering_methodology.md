# LLM-Assisted Reverse Engineering Methodology

> A structured approach to leveraging large language models for effective reverse engineering.

---

## Principle 1 — Data-Driven: Global First, Then Local — Conquer the Unknown One Step at a Time

Begin with a comprehensive analysis of the target to give the AI a full picture of the overall structure. This allows it to form appropriate hypotheses and prevents it from making wild guesses that lead to wasted effort. Once the global context is established, drill down into individual components one by one. It is best to follow a single execution path from start to finish — this keeps the AI focused, and enables the production of incremental documentation that is easy to organize and review.

**Key practices:**

- Feed the AI a complete overview of the target before narrowing scope.
- Trace one code path end-to-end rather than jumping between unrelated areas.
- Generate stage-by-stage documentation to capture findings progressively.

---

## Principle 2 — Validate Conclusions Promptly

During reverse analysis, conclusions must be verified in a timely manner. This can be done by inserting hooks at relevant locations to compare the results generated offline against those computed by the running application in real time. Ensuring consistency between the two confirms that the analysis is correct before proceeding further.

**Key practices:**

- Hook at strategic points to intercept and observe runtime values.
- Compare offline/static analysis results with live runtime output.
- Do not advance to the next stage until the current conclusion is confirmed.

---

## Principle 3 — Produce Incremental Summaries

After completing each sub-goal, the AI must generate a thorough and accurate summary — no shortcuts. This document becomes the sole reference for all subsequent work. Without it, the model is likely to hallucinate due to an overwhelming context window, resulting in incorrect analysis and wasted effort.

**Key practices:**

- Treat each summary as the authoritative record for that stage.
- Summaries must be precise and comprehensive, not cursory.
- Use these documents to reset context when starting a new conversation or phase.

----

# LLM 辅助逆向方法论

> 一套利用大语言模型进行高效逆向工程的结构化方法。

---

## 原则一 — 数据驱动：先全局，再局部，逐一击破未知

必须先对目标进行一次全面分析，让 AI 了解整体结构，做出恰当的假设，防止 AI 随意提出假设而产生大量无用功。了解全局之后，再进入局部逐一分析。最好是沿着一条执行路径追踪到底——这样 AI 能够专注地完成工作，并形成阶段性文档，便于整理和分析。

**关键实践：**

- 在缩小范围之前，先向 AI 提供目标的完整概览。
- 端到端地追踪一条代码路径，而非在不相关的区域之间跳跃。
- 分阶段生成文档，逐步记录分析发现。

---

## 原则二 — 及时验证结论

在逆向分析过程中，必须及时验证结论是否正确。可以在相应位置进行 Hook，比较离线生成的结果与应用实时计算的结果是否一致，以确保结论正确后再继续推进。

**关键实践：**

- 在关键位置插入 Hook，拦截并观察运行时的值。
- 将离线/静态分析结果与实时运行输出进行对比。
- 在当前结论得到验证之前，不推进至下一阶段。

---

## 原则三 — 阶段性总结

在完成一个小目标后，必须让 AI 进行阶段性总结，不能马虎。一定要生成一份准确且详尽的文档，这是后续工作的重要参考，也是唯一参考。否则，大模型会因上下文过长而产生幻觉，从而导致分析偏差和无用功。

**关键实践：**

- 将每份阶段性总结视为该阶段的权威记录。
- 总结必须准确、全面，不能流于形式。
- 在开始新的对话或阶段时，使用这些文档重置上下文。
