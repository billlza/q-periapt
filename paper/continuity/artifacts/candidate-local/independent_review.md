# Candidate-local composition：独立数学审查

状态：**PASS — 已完成并绑定冻结源码。** MD v0.2 与 `candidate-local-accounting.tex` 的独立数学复核通过。作者代理已确认这两份数学源冻结；此记录不编辑证明源或论文正文。

## 结论

已核读的 origin-anchored stopping、共同 native experiment 中的精确分解，以及 candidate-local composition 命题在其明示假设下成立。未发现需要撤回等式或放大最终 native residual 的数学错误。连接命题保留真实 stopped-interface 比较为前提，正确地允许各候选使用不同的 real-component 与 ideal-component continuation。

## 独立推导与核对

### 1. 尚未选定 cut 或另一预约尚未出现

假设候选 `j` 的一个原始预约 `o` 已发生，且捕获的完整版本 `v` 满足 `subject(v)=session(o)`、`res(o)≤save(v)`。任一最终满足 `E∧A∧(I=j)` 的延续都必须让所选会话等于该预约的固有会话，并满足 `c<res(o)`；于是 `c<save(v)`。累积获取集合已永久包含 `v`，与原 eligibility 中的 acquisition 条件冲突。因此证书不需要知道最终 cut、挑战消息或另一成员预约。

这里用到的是匹配的对象主体与不可变时间关系；`Retains(v,o)` 是证明该因果关系的一种来源证据。实际完整版本路径不能由 report dependency、摘要或 key-only batch fragment 替代。这与已核读的 `security-model.tex` reservation origin、acquisition 和 eligibility 定义一致。

v0.2 新增的时间刻画也成立。定义空集合最大值为 `−∞` 后，全部已获取匹配版本的原始保存时间最大值 `L_s` 满足：原 acquisition 条件等价于 `L_s≤c`；当两个预约均已发生，合并原预约时间条件恰得 `L_s≤c<min(res(g),res(a))`。该等价仅针对这些时间/获取条件，原稿保留了其余资格与归属测试。一个已发生预约的 `res(o)` 已足以给出矛盾证书，不需要给未来预约预设时间。

### 2. Free stop 与 charged stop 交织

在同一完整 native run 上考虑候选 `j`：

| 情况 | stopped 候选分数 | native `Z_j 1_{¬B_j}` | 理由 |
|---|---:|---:|---|
| 两种 stop 均不发生 | `Z_j` | `Z_j` | 同一代码与终局分数 |
| `B_j` 先发生 | 0 | 0 | 右侧的 `1_{¬B_j}` 为 0 |
| `U_j` 先发生，之后没有 `B_j` | 0 | 0 | 全延续零贡献性质给出 `Z_j=0` |
| `U_j` 先发生，之后发生 `B_j` | 0 | 0 | 两种原因均使右侧为 0 |
| 两种 stop 同时发生 | 0 | 0 | 无需人为规定先后优先级 |

两台机器只需保持停止前相同前缀分布。停止后的 native 延续仍可用于数学期望；候选 reduction 无需执行该延续或知道未来 selector。这给出准确等式

`E[z_j^stop] = E_nat[Z_j 1_{¬B_j}]`。

### 3. 精确共同 native 分解与 residual 只收费一次

在 `A` 上，`I` 是唯一候选，因此在同一个 native trace 中有

`Σ_j Z_j = Z 1_A`，且 `Σ_j Z_j 1_{B_j} = Z 1_{A∧B_I}`。

结合上一等式即可得到原稿等式 (2)，不需要 selector 与历史独立。`E∧¬A` 与 `E∧A∧B_I` 不相交；两项概率相加至多为 1。同一物理捕获可以触发多个候选的 `B_j`，但最终 `I` 只有一个，因此 native projection residual 不应机械乘以候选数量。

某候选的 `U_j` 也不能升级为全局 halt：别的候选仍可能成为唯一合法挑战的最终归属。原稿双会话例子准确展示了这个区别，没有把一个挑战 bit 转移给另一个 send。

### 4. Candidate-local 游戏不需要共用一个 V

每个候选的 `ρ_j` 比较它自己的 stopped native experiment 与 `V^[j]`；每个 component hop 又在这个相同 `V^[j]` 与自己的 `Ideal_j` 之间比较。逐候选的三角不等式合法，即使这些中间游戏由不同的 opaque source、report closure 或 stop rule 产生。

`Ψ_j` 必须在每个比较世界中重新计算该世界的 eligibility、attribution、selector 与 test coins，不能移植 native 终局事件。当前陈述已经明确这点。各个 `b_j` 来自不同 ideal continuation，故 `Σ_j|b_j|` 不能凭 native 的互斥性归一化；原稿保留该和是正确的。

### 5. 三值 score 的转换常数

对于 message score `Ψ_j∈{-1,0,+1}`，

`E Ψ_j = Pr[Ψ_j=+1] − Pr[Ψ_j=−1]`。

正、负两个事件分别应用固定 pair 的 bit bound 后，得到 `a_j^+ + a_j^- + 2δ_j`，没有遗漏系数。native 的两项 residual 以概率界定相应带符号期望；再对候选和应用三角不等式，得到所述总界。因为 `|Z|≤1`，可截断至 1。将不合格执行以独立公平猜测补全后，普通 message advantage 等于 centered score 的绝对期望的一半，因此最后的 `1/2` 也正确。

一般 `S∈[-1,1]` 足以支持精确分解；使用仅有两个 `±1` 事件的 component-hop 转换时须限定三值分数。v0.2 与 TeX 均已显式标出这一区别。TeX 直接陈述普通 message advantage 界，MD 先陈述 centered-score 界再除以二；两者完全等价。

### 6. 量子路径

证明可按同一经典 ledger 前缀上的 subnormalized quantum instrument 分支理解。原实验和 stopped 实验在停止前执行相同操作；停止分支直接输出零分数。`U_j` 的全延续性质使该分支所有原实验终局 scored outcomes 的权重均为零；`B_j` 分支被明确分配给 residual。线性期望给出同一等式。

这不要求同时运行所有 candidate reductions，不要求复制 adversary state，不测量 quantum oracle queries，也不以观测隐藏量子路径来判断 future selector。所有候选 monitor 都是原实验已声明经典 ledger 的可计算函数。原稿的量子说明与此解释一致。

## 与现有模块的实际连接

已对照 `work/joc_round3/manuscript/security-model.tex`、`native-correspondence.tex`、`computational-roadmap.tex`、`opaque-rendering.tex` 与 `report-composition.tex`。本连接命题没有将 key-only report projection 误认作完整目标会话 acquisition，也没有更改原 eligibility。

原稿公式 (3) 保留 `ρ_j` 为**实际 stopped-interface 的 score 比较**。这是将现有记录/报告模块实例化到具体候选时所用的接口前提，而不是由会计分解自动获得的新定理。报告中的 `2ε_rep` 和记录接口中的 `2(ε_com+δ_nonce)` 是由 bit difference 转为 bounded-score difference 的系数；`ρ_j` 必须按实际比较链包含它们及前置 source correspondence，不能遗漏或重复计入。当前连接陈述已正确保留这一责任，没有据此声称完成新的全 native 保密定理。

## 审查边界与冻结信息

本记录审查新连接证明的数学有效性以及其与已写明模型的吻合；没有重新运行 native 实验、符号证明或 CI。最终冻结状态已由理论代理确认。本次数学审查未发现实际错误；一般分数与三值 component step 的范围已在最终稿中明确。

审查完成时间：`2026-11-07T19:59:54Z`。

| 已冻结的审查对象 | 字节数 | SHA-256 |
|---|---:|---|
| `candidate_local_composition.md` v0.2 | 20195 | `62132fa847d02a92e8a14af6a15d939607c71ef057c4d439888fe51c9ef5122a` |
| `candidate-local-accounting.tex` | 8913 | `4a38c6bb00c70f2611c2395aec754c0af6b8231a8e3f94e027cf1a17b657865d` |

结构化审查结果及本审查记录本身的 SHA-256 见同目录 `independent_review.json`。冻结后任何数学源修改都需重新绑定；当前结果精确针对上表两个文件。
