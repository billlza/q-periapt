# Opaque-rendering LaTeX 整合版：独立复核

审阅日期：2026-11-07。审阅对象为 `work/paper_round2/manuscript/opaque-rendering.tex`，逐项对照冻结的 `work/theory_increment.md` v1.2、保存的两个 record-commitment 模块，以及主稿中的 recovery eligibility 和 adaptive accounting 定义。本审阅只写本文件，未修改主稿或重新运行实验。

## 结论

**最终核读版通过：在声明的有限、固定候选 image/intent 接口及沿用的 commitment 条件下，未发现剩余实质数学错误或相对 v1.2 的论断扩大。** Explicit table algorithm、完整记录 equality lemma、statistical coupling、real-to-table composition 均保持冻结证明的内容。正文现在以 `epsilon_com` 表示 commitment 子步骤，不与完整 native-to-virtual connection 的 `epsilon_rec` 混用。

复核期间发现的原始保存时间措辞、显式 oracle/output 边界及 terminal-test coin 说明均已在作者最终版本中修正；下文按该最终版本给出结论。

| 文件 | SHA-256 |
|---|---|
| `work/theory_increment.md` v1.2 | `98e0df8b8536d5d43cd191a0a9851676345e8c20aebe82a298c4d86dd6b8035e` |
| `work/paper_round2/manuscript/opaque-rendering.tex`，最终核读版 | `94259f696bd907bca372b8df7cd331b5c3bfa79f3724526d684f0e86a96ccfb5` |
| `work/paper_round2/source_snapshot/docs/continuity/HIDDEN_RECORD_COMMITMENTS_V1.md` | `c0b6b8fc8de35314f0fa66dc133fda269371882811ee2d134c10e72dbfa9191d` |
| `work/paper_round2/source_snapshot/docs/continuity/MULTI_RECORD_COMMITMENTS_V1.md` | `bd2f8dde2dd2e751c65323e753a4348c2ea2fc8eb8bd457ebab24ebb36134135` |

## 逐项核对

### 1. 范围与原始 acquisition 谓词

LaTeX 仍构造有限 typed image/intent 接口的算法，令公共协议计算通过共同接口 `F` 执行，并保留 `F` 原有安全论证。导言把本节定位为 Proposition `prop:adaptive-accounting` 的 image/intent contribution，没有把它提升成完整 native correspondence 或整个 `epsilon_rec` 的已求值界。

最终 acquisition 例子明确要求取得原始版本 `v`，满足 `subject(v)=s` 和 `c<save(v)`，且由 original-record provenance 决定保存时间。后续 aggregate 携带同一版本时仍沿用该时间。这与 `security-model.tex` 的 eligibility 最后一项和 `cor:target-acquisition-stop` 完全对应。

这个修正有实质作用：一个 pre-cut target version 被 sibling write 放入 post-cut aggregate，并不因 aggregate 的新时间自动成为 post-cut target version。最终文本保留了这一已有区分，未增强排除条件。单独许可的 projection 仍按自己的输出接口处理。

### 2. `epsilon_com` 与总 `epsilon_rec`

`computational-roadmap.tex` 用 `epsilon_rec` 约束完整 native/virtual 正负 score events 的 binary distinguishing gap。本节的 `epsilon_com` 只约束 designated-private rows 的 commitment replacement；额外 equality representation loss 为 `delta_nonce`。

Real-to-table bit bound 正确为

\[
\min\{1,\epsilon_{\rm com}+\delta_{\rm nonce}\},
\]

对应 `[-1,1]` score bound 正确为

\[
\min\{2,2(\epsilon_{\rm com}+\delta_{\rm nonce})\}.
\]

本节没有令总 `epsilon_rec` 等于这个子步骤界，也未漏掉 centered-score 转换的系数 2。`q_i<=1+5K_i` 与一个 image-head domain、五个 intent-digest domains 匹配；不同 original headers、精确 retries 及 source module 的 distinct-input 条件保持一致。

### 3. 完整 prefix、fresh invocation 与 cache 身份

Head cache 使用 sealing invocation `i`；intent identity 使用实际完整 prefix `(i,P)`；intent digest cache 再加入 domain，成为 `(d,i,P)`。`P` 包括本次实验实际使用的 head，而不是固定在真实实验中的旧 head。Changing a commitment 后，其所在实验后续 prefixes、checks 和 outputs 都重新使用该值。

同一 image 的 intent-authentication key 固定，tag 决定 prefix 长度；不同 fresh seal 即便 recipe 或 reservation source 相同，也具有新 image identity。Exact copy/retry 保留原 identity。Equality lemma 因此证明的是完整 wire equality，而非误将 reservation origin 相同当成 wire 相同。

这精确保留 v1.2 和 `MULTI_RECORD_COMMITMENTS_V1.md` 要求的 cache/identity 语义。

### 4. Atom-free rows 保留真实 bytes 和 hash

只有包含 opaque block 的 designated-private image rows 使用独立 uniform cached commitments。Atom-free rows 由已知 recipe、nonce 和可用 local keys 真实渲染并调用共享 oracle，正常支持 raw-byte acquisition 与之后的 hash 检验。

Replacement accounting 对这些 rows 取 `q_i=0`；其真实 ordinary-oracle work 仍计入完整 reduction 的 `Q_i`。这避免了“返回真实 raw bytes，却仍为其返回独立 ideal head”的可区分实现。Known rows 也计入 `M`，使 private/known record 的 equality 比较包含在 nonce collision accounting 中。

### 5. 本地 primitives 与公共输出边界

最终 Seal 定义已明确：local encryption 和 intent authentication 使用规定的固定算法，不额外调用 shared SHA3；reply 只包含 handle、length、declared non-nonce metadata，`N_i`、`C_i` 和 opaque blocks 保持私有。

这与 single-record module 的固定 deterministic private maps 及没有额外 raw-nonce-dependent channel 的条件一致。完整 reduction 的其他公共 hash 调用由 `Q_i` 统计。本节没有把一个新的联合 SHA3/SHA256 oracle idealization 隐含放入原 commitment hop。

### 6. 终局测试随机性与 centered score

`D` 的输入限制为共同 public view、available metadata/event ledger、`F` outputs 及自身 test coins；最终版显式包含 retained application challenge bit。应用 challenge bit 在抽样时是独立的本地 test coin，随后可以通过应用 challenge 与 transcript 相关；它不是 component KEM challenger 的隐藏 bit。

这使 recovery centered score 可由共同实验的可用输入计算。该 theorem 没有赋予 terminal test 额外读取 storage nonce、opaque atom 或 materialized private wire 的通道。期望是 unconditional expectation，未除以 eligibility probability。

### 7. Fixed 与 adaptive stopping

固定候选的停止条件由实际 provenance/acquisition event 在 raw serialization 之前触发，永久使该候选 eligibility 为 false。Unavailable-object requests 保留 ordinary errors；单纯无法计算某个 output 不构成停止事件。

末段对 adaptive origin-pair event `E_j` 要求：同一个 computable event 必须在**每个 continuation 和所有仍可归属于 j 的最终 target choices**上令 `E_j` 为 false。该条件与冻结 v1.2 的 all-continuations 要求相同。文本未把一个候选失效升级为整个多候选游戏终止。

### 8. Nonce 界及 composition 顺序

`M` 覆盖所有 fresh seals，包括 persistence 失败的尝试和 atom-free images；exact retries 不增加 `M`。每个新 nonce 在 invocation 决定之后仍独立 uniform。Adaptive scheduling 因而保持

\[
\Pr[\text{some nonce collision}]
\le \min\{1,\tbinom M2 2^{-n}\}.
\]

在无 collision 的 prefix 上，nonce 的固定显式 offset 区分 fresh image wires；canonical prefix 和 fixed key 区分 intent wires。证明不需要私有 block 值互异，也不需要额外 encryption injectivity。

Real-digest composition 顺序正确：先把 observable raw-handle equality 换成 structural equality，支付一次 nonce loss；随后应用既有 commitment hop；其 structural ideal game 与 table algorithm 完全一致。这保留 source module 对额外 raw-nonce observations 的限制，也没有重复支付两次 nonce loss。没有 private-wire equality operation 时，第一步消失，附加 representation loss 为零。

### 9. 量子 adversary 的 coupling

Record interface 的输入输出仍为 classical，公共 oracle 和 `F` 的执行保持共同定义。在 coupled good prefix 上，同样的 classical replies 与 oracle transformations 保持 adversary 的 quantum state 相同。碰撞事件只涉及 locally sampled classical nonces，证明不测量或采样 adversary 的 quantum oracle queries。

因此 bit bound 的事件概率系数 1 和 `[-1,1]` score bound 的系数 2 都成立。该论证没有把 quantum query history 当成可读 classical transcript。

## 复核期间已解决的整合问题

1. 原先 “a complete selected-session image saved after the cut” 的压缩表述已改为 original version `v` 的精确 subject/save 条件，并明确 later aggregate 不重置该时间。
2. 已恢复本地 encryption/authentication 无额外 shared-SHA3 调用，以及 Seal 不输出 nonce/ciphertext/private blocks 的条件。
3. 已显式恢复 application challenge bit 作为 retained test coin。
4. 已将引用改为实际存在的 `cor:target-acquisition-stop`。

上述是将冻结已审阅证明准确写回论文的修正，没有增加新的实验或产品验收要求。最终版本可以作为已完成的 finite typed-interface theorem 纳入主稿；其他原有 source-correspondence 或 report-output 问题继续由其各自命题处理。

## 检查方式与边界

本次直接核读 LaTeX、v1.2 及两份 commitment 模块，并对照主稿 `security-model.tex` / `computational-roadmap.tex`。逐步检查了 equality 两个方向、缓存身份、known-row rendering、终局可计算性、stopping permanence、collision coupling 和 hybrid coefficient。没有新增 native runtime、baseline、Tamarin 或外部文献检索，也没有更改冻结笔记。
