# Q-Periapt：主结果与投稿准备度定向审查

审读基线：integration `0e2ca2d79ab0000bed79130cec97b31181e936ea`，其 canonical paper 对应 `4fde471641150c68a08b56e728067c72b39ab346`；`paper/continuity` Git tree 为 `231bacf92ec72a8897d7e9229b1ff95c00c5f08f`。本轮为只读主线审查，另写了新的 ordinary-KEM 桥接草案，交由 root 独立复核和整合。

## 结论

这已经具备认真冲刺 Journal of Cryptology 的实质研究内容。支撑判断的是完整的原始来源安全连接、需要处理自适应选择与持久状态的具体归约，以及两种 bootstrap 来源的非平凡组合；页数、测试数和 CI 状态没有进入这个判断。

在逐读的主结果与共同依赖中，没有发现一个使明示定理失效的反例或未闭合数学环节。原来的 operational ML-KEM 优势是明确给定游戏的安全参数，因此已有结论在该假设下成立；本轮给出的 deferred-challenge proposition 进一步把它接到普通 IND-CCA 优势。root 已独立审读并确认该推导，正在整合。

投前剩余工作的重点是相关工作的精确定位和主论点收束。根代理负责正在补充的原始文献比较，本文不预判尚未读完的比较结果。现有主张没有把“全面性能领先”作为结论，所以另跑一轮无针对性的全面 baseline 不构成本轮投稿门槛。

## 主线闭合：具体依据

以下路径均相对仓库根目录 `paper/continuity/`，定理标签比集成后可能变化的页码更稳定。

| 连接 | 已成立的内容与阅读依据 |
| --- | --- |
| 原始来源、捕获和读取 | `security-model.tex` 的 `def:reservation-origin` 明确 `res(o)` 是原始随机输入的抽取事件，`save(v)` 是原始版本进入持久获取面的事件。`def:record-acquisition` 将已获得与可读取分开。`guarded-provenance.tex` 的 `thm:guarded-normalization` 对固定公共派生边的有限图给双向构造证明；每条路径内是合取，路径之间是析取。其作用是精确记录语义。 |
| 私有记录可模拟 | `opaque-rendering.tex` 的 `thm:opaque-rendering` 和 `cor:real-to-opaque` 显式构造目录、原始 seal / intent 缓存、结构相等、真实错误与 uncertain commit 的处理。先比较可构造真实记录，再安装未知 KEM tape，避免用不存在的序列化能力作为前提。192-bit nonce 的相等成本和隐藏输入比较分开计入。 |
| 允许自适应 cut 的停止 | `candidate-local-accounting.tex` 的 `lem:adaptive-origin-stop` 用 `c < res(o) <= save(v)` 给出对所有未来候选 cut 有效的永久反证。`lem:native-local-score` 首先在一个原始 native game 内划分事件，再比较各自的 hybrid；没有把多个不同理想世界当作一组互斥事件。 |
| 依赖报告 | `report-composition.tex` 的 `thm:report-reverse-composition` 按反向创建顺序替换受保护的 HMAC 行，使后续包含未知原始 key 的报告已经理想化；早期行只依赖已知键。允许的 raw-key projection 以原始游戏的实际 residual 计入。`live-core-instantiation.tex` 给出了完整 call surface，并据此证明核心 `B_j` 为空；报告扩展没有被误当成核心的无代价组成。 |
| 完整混合贡献与根入口 | `contextbound-connection.tex` 的 `lem:cb-hidden-component` 以全部十个真实字段作为编码、其余九个字段作为表索引，保留数值相等与 exact aliases。`lem:cb-native-root-use` 把目标原始调用的所有使用连接到同一旧 root 和完整 root-info。`joint-primitive-bounds.tex` 的 root-entry 段落给出实际 Extract/Expand 比较，完整计入后续工作。 |
| 联合 key schedule | `thm:joint-message-leaf` 以及 `lem:appendix-joint-hmac` 同时保留 root 在 HMAC key / message 两侧的使用，处理真实确认和 ACK、可公开 successor root、其他 traffic entries 与选中消息的 successor seed。`lem:joint-expand-blocks` 根据 HKDF 的完整 info / counter 编码给出精确表重写，才移除内部反馈带来的额外 raw use。 |
| 原始来源归属 | `source-attribution.tex` 的 `lem:executed-slot-stability` 和 `prop:executed-source-attribution` 对先持久保留再计算的真实顺序作归纳；final selector 使用执行槽，不会把一次失败的未执行 draw 当成接受交换的来源。`thm:native-mldsa-reservation-bridge` 保留开放的 randomizer、原始消息 ledger 和共享 SHAKE，接到 ordinary hedged ML-DSA。于是 executed selector 的 attribution residual 已有实际 primitive 上界。 |
| 在线选择消息 | `chain-prefix-continuation.tex` 的 `thm:online-chain-leaf` 允许早期消息键影响后续 Mark，选择点为全部 aliases 上首次私有计算之前。`native-chain-composition.tex` 的 `lem:native-online-chain-correspondence` 包含 receive-side skipped steps、验证失败和持久写失败，并证明一次标记的材料与索引至多一个原始 encryption tuple。`thm:native-online-message` 将其接回原始 native eligibility，同时给 confidentiality 和 integrity，未新增消息索引猜测因子。 |
| reply-source bootstrap | `bootstrap-authentication.tex` 的 `lem:bootstrap-reply-origin`、`lem:bootstrap-validation`、`thm:bootstrap-source-schedule` 和 `thm:bootstrap-terminal` 依次给出原始 PQ 来源、恢复 owner 的真实 validation、完整 signed-wire class 与有效 descriptor 的对应，以及历史 responder activation。接口包括初始贡献、传统材料和 initiator signer 已公开的存活来源情形。 |
| initial-source bootstrap | `bootstrap-entry.tex` 的 `thm:bootstrap-joint-entry` 保留短 initial-confirmation Extract 与长 Extract 可能共享的原始压缩点。`bootstrap-initial-source.tex` 的 `thm:bootstrap-initial-schedule` 先替换同一原始来源的完整服务，再按在线首次分配的 long-parent rank 划分；异质 `L_j` 只乘后续 tail，raw-acquisition union 在第二次划分前只计一次。`cor:bootstrap-initial-terminal` 将其接到同一 ACK-only endpoint。 |

本轮没有重跑历史 Tamarin 或 native 实验，也没有逐行重审所有 Rust 源文件。这里的数学结论来自逐读当前命题、证明、接口及其指定 source correspondence；历史运行证据和源码细节沿用论文明确固定的 artifacts。此说明限定审查范围，不改变这些已保留结果的地位。

## 本轮新增的实质闭合

`kem-ordinary-bridge.tex` 的 `prop:kem-deferred-challenge` 构造普通挑战先给的 IND-CCA 归约：持有挑战密文和 key，只先给 pk；前置 decapsulation 若遇挑战密文则停止为零，否则保留真实答案；在原始 controller 请求时才发布挑战。

固定静态公共 oracle 与诚实生成的 key 后，完整的真实前置过程与尚未使用的 uniform `m*` 独立。若 K-PKE 对挑战成功恢复消息，前置 `q_pre` 个不同密文只能命中至多 `q_pre` 个 `m*`。故每个 Boolean operational advantage 以 ordinary advantage 加

`zeta = min(1, q_pre / 2^256 + delta_mr)`

控制。其中 `delta_mr` 专指挑战的 K-PKE message-recovery failure；原有 KEM shared-key correctness 项保留。两个 key-bit 分支具有共同的前置命中概率，因此只需一个 `zeta`。signed-score 的现有两倍换算和两个 `a_j^+ / a_j^-` 事件各自计费仍保持正确。该桥接不增加原始来源或消息位置猜测，也不扩大 selected tape 的允许 opening 面。

## 对 JoC 六项标准的判断

官方依据为 https://www.iacr.org/jofc/referees.html 。

**Correctness。** 当前主结果在明确的 finite native interfaces 和公共 ROM/QROM 模型内形成闭合证明链。条件中的 one-authoritative-history、first-private-allocation marking、原始 acquisition 规则分别控制可重放来源、可在线嵌入的值和未知记录字节的处理，都是与结论直接对应的条件。bootstrap 的 marked-byte acquisition residual 明确限定其尚未实例化的 joint journal / derived-key ciphertext comparison；它不扩散成对 established-session message theorem 的否定。

**Depth。** 深度主要来自可以执行的交互模拟与正确的依赖次序：source-dependent records / report keys、各候选独立的早停、共享压缩 oracle 中的 key/message 交叉使用、公开 predecessor / successor 下的在线消息选择、以及初始源的两层计费。guarded reachability 本身是直接的语义归纳，论文应把它作为后续安全定理的清晰基础，而让这些实际解决困难的组合承担主要技术叙述。

**Originality。** 本轮确认了具体新增机制和性质：原始 draw / version / physical image 三个身份的保持；对既有 selector 的严格来源归属；reverse-order report simulation；在真实失败／重试顺序下的在线 chosen message 比较；初始 confirmation 与后续 adaptive reply families 的共同服务。采用 ML-KEM、HMAC 和既有 QROM 原语结果并不消去这些新组合的贡献。其相对最接近工作的确切优先性由 root 正在进行的原始文献对照确定。

**Potential breadth。** 私有 image/intent、依赖报告、原始槽选择、签名 randomizer 和有限 key-family 的接口具有超出一个 Rust 产品的可复用对象。主文需要先给清楚的抽象问题和结果，再展示 Q-Periapt 的实例化；字节长度、文件布局和 release provenance 服务于证明与复现即可。

**Scholarship。** 原语假设与引用给了明确游戏和 theorem locator；ordinary KEM 桥接进一步消除读者对非标准组件优势的疑问。关于 state reset、failure recovery、ratchet leakage 与 Squirrel 的最近文献定位由 root 审读，尚未完成的比较不被当成已经发现的 novelty defect。

**Exposition。** 当前核心文字以贡献和机制为主，没有连续自我免责句式，也没有把未做全面 baseline 表述成无贡献。真正的投前阅读负担是贡献主线过多：原始来源语义、private-state simulation、message composition、ML-DSA、purpose key、bootstrap 与实验都在摘要中占据独立位置。建议明确一个中心安全结果，其余分为建立它的技术与展示其覆盖面的实例。这里需要聚焦和组织，不需要继续增加定理数量。

## 可以结项的研究事项

1. 当前 provenance / acquisition 语义和固定派生边下的 exact guarded normalization。
2. 明示接口下的 image/intent 与 dependent-report simulation，以及原始 native-game candidate accounting。
3. executed-slot source attribution 与 ordinary ML-DSA reservation bridge。
4. next-rekey confidentiality / selected-root authentication，以及 native online selected-message 的 confidentiality / integrity。
5. 两个 bootstrap surviving-source profile 的 schedule connection 和历史 activation；initial-source 的 source-versus-family 计费已闭合。
6. 相关版本固定的 symbolic theorem、separating executions 与已完成 matched evaluations 可作为既有成果报告。它们各自有清楚用途，无需用新增重复运行来充当数学贡献。

ordinary KEM 新命题在 root 完成整合和构建后也可以结项。

## 投前剩余工作与可控时间

建议给用户的工作量判断是：**若本轮最近文献核对没有要求改变中心命题，约 7–15 个专注工作日，可形成一版结构完整、可认真投递 JoC 的投稿稿；按通常日历安排约 2–3 周。** 这是成稿时间估计，投稿后的评审决定和周期另行发生。

这个估计对应具体事项：把普通 KEM 桥接与相关工作差异写入当前稿；将 abstract / introduction 的主论点收束为一条从原始来源到在线消息安全的清晰路线；对整合后的主定理、变量、游戏和 source pins 做一次一致性通读；最后完成编译、引用和提交 artifacts。可以在相邻工作日并行完成。已经完成的数学工作不重新排成未完成事项。

更强的捕获密文字节扩展、完全一般的计算型多 epoch 组合、更多性能调优或新的协议 baseline 都可以独立发展。只有中心主张实际依赖某项时，它才成为投稿前的依赖。当前稿的主要结论已经明确其有限计算接口与 unbounded symbolic 结果的各自范围。
