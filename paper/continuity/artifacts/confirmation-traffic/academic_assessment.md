# 独立学术评估：当前主结论与下一项研究依赖

审查输入是论文 `da521d8388f5f0c64697387bf80b0b5b7837fb34` 的 68 页源码、研究交接和相关冻结证明，以及原生实现 `228c944fc476e3e57d6c08063cacb19bca5b360e`。本轮新增内容在 `confirmation_traffic/`，由主代理审查后集成。本文评估研究内容和论证组织，不给录用概率。

## 目前已经成立的核心成果

这篇论文已经具备可以独立陈述的密码学研究主线：**持久化随机性来源与记录获得历史怎样进入恢复安全实验，以及怎样在隐藏原始随机币时继续模拟实际实现的公开行为并完成密钥推导归约。** 它的新增内容可以落在具体定义、模拟机制和定理上。

第一组结果是原始 reservation、不可变记录版本和物理副本的区分，以及获得记录与后来获得解封装能力的区分。别名规范化保持同一原始操作；带合取条件的路径刻画精确表达“已经取得的密文与已披露的密钥一起打开来源”，同时容纳多个副本。这个模型支持复制、重封装、删除和迟到的密钥披露，其研究对象与实现中实际存在的持久化历史对应。

第二组结果是构造性的计算连接：隐藏随机币时模拟 image、intent、公开承诺和精确重试；按逆因果顺序组合包含早先私有报告密钥的不可变报告；在最后恢复 cut 和归属候选可能自适应选择时，用候选局部计分与可证明的永久零分支进行组合。这些机制解决的是归约必须执行的实际接口，已经超出只提出一个 exposure 定义的阶段。

第三组结果是完整 ContextBound 元组到统一贡献、实际 root Extract/Expand、联合确认与流量派生、选定首条消息密钥的连接。它保留同一公共压缩 oracle、盐/PRK 类别名、完整 info 的自适应选择、真实确认/ACK、后继 root 和 next-seed 披露。有限多 root 初始化和 SDK purpose-key 表又给出可复用的接口形式，并对应真实字节编码与对象生命周期。文献中的量子 hash、HMAC/NMAC 和 HKDF 原语结论保持其原作者归属；本项目的贡献是所定义的接口、精确别名及依赖处理、完整的组合和实际源程序连接。

第四组证据是多 epoch 的符号保密结论、带原始来源的实际进程中断/恢复与延迟 receipt 执行、有限 exposure 模型和源映射。这些证据各有明确作用：符号模型覆盖其协议语义；原生执行支持实际机制与反例；源审查连接接口；计算证明给出相应量化结论。论文已经可以正面确认这些成果。

本轮把 live-core 的记录比较项代入计算主界，并将确认来源和第一条消息完整性从已有联合密钥表推出。这样应用接口中的确认 transcript、验证结果、nonce、AAD、私有明文边界都有了可复查的对应物。

## 最影响当前主结论的一项未闭合连接

一般消息实验的 `eta_attr = Pr[E and not Attr]` 仍然有实质意义。它不能从“代码检查了身份签名”直接改为零：同一目标 epoch 中，第一次 reservation `g1` 的首次写入在任何完整 durable target 形成前失败，重开后 `g2` 参与正常交换；选择器仍可点名满足 session/epoch/role 元数据的 `g1`。这条执行无需签名伪造或 hash 碰撞。既有一般定理已经对它正确计费；它阻止的是另一个更强的无残差归属主张。

因此，下一项最有价值的研究问题是**实际来源选择与身份签名服务的完整归约接口**。一个明确的方向是在保留的 KEM plan 首次进入实际私有计算时登记原始来源，并把这一在线接口与一般任意句柄 selector 区分。随后证明接受的响应/完成消息对应这些源操作，或者产出新签名消息伪造/完整 transcript 碰撞。代码已给出 purpose、完整 body、role、session、epoch、parent 和完整控制 wire 的绑定点。

签名归约还要处理 `SigningReservation` 的真实持久化语义：其记录含签名随机币，重试重用它们，允许的旧记录观察需要与签名 challenger 一致。通常的“给消息、返回随机签名”接口不会自动给出可写入 journal 的匹配随机币。这个精确的程序到签名游戏连接尚未完成。本轮保留归属残差，并把相应源检查和反例交付；不把这一个接口依赖扩展为对其他已证明模块的否定。

相比之下，live-core 的两个问题已可结项：`rho_j` 有现成记录模拟成本可直接代入；在该 core 穷尽定义的观察面上，额外 charged projection 接口为空，`eta_proj = 0`。允许任意 secret slices、private-wire nonce、额外公共明文调用或 cleanup/report 扩展时，应按它们真实接口使用已有计费规则。

## 与最接近既有工作的定位

| 一手研究 | 已有结论中与本文直接相接的部分 | 本文应明确呈现的增量 |
|---|---|---|
| [SCKA / vulnerable message sets，USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf)，Definition 3.2 / Theorem 3.3 | vulnerable set 已覆盖当前链、已经产生的未来 epoch 密钥和未接收的乱序消息，并给出消息层组合 | 原始操作在多个持久化密文中的获得/打开历史，以及没有原始随机币的构造性记录模拟 |
| [Triple Ratchet，Eurocrypt 2025 作者全文](https://cs.nyu.edu/~dodis/ps/triple-ratchet.pdf)，Remark 4.3 | 预先产生的下一 epoch 材料会影响 compromise 后恢复的 epoch 计数 | reservation 采样、持久化、计算、发布和确认的分离，以及复制/迟到披露后的同源一致性 |
| [Robust Channels，JoC 2024](https://link.springer.com/article/10.1007/s00145-023-09489-9) | 对不可靠网络区分 robustness、integrity 与隐私，并明确反复伪造尝试的计费 | 当前实际首条消息与确认验证的接口/计数，持续保留失败和异步状态；本轮结果的事件范围需与全 channel robustness 区分 |
| [Session Handling，USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/cremers-session-handling) | 会话组合和 clone 行为可改变端到端 PCS，单条 ratchet 的安全不能自动迁移到 conversation | 明确 authoritative ownership、原始来源与跨记录别名；全会话层扩展可以独立研究 |
| [When Messages Are Keys，CRYPTO 2023](https://eprint.iacr.org/2023/861.pdf) | HMAC swapped-input PRF 需要合适输入域，其安全并非无条件成立 | 本文的具体 32-byte hidden input、同一压缩 oracle、双角色 root 使用、完整自适应 info 表和源生命周期的组合 |

现有 related-work 已经正确引述 SCKA 和 Triple Ratchet 的关键位置，避免把预采样的未来材料本身写成首次发现。最有帮助的进一步组织是围绕同一个可核对问题解释新增性：给定一个原始操作，什么历史使其随机性可恢复，重启和副本怎样保持该事实，归约怎样在观察继续发生时执行协议。这样读者能够清楚区分新定义、组合定理、已有原语和具体实现证据。

## 投稿文本最值得完成的组织工作

主结果宜在同一处给出“实际应用接口—假设—保密界—认证界—来源映射”的连续论证。当前证明模块数量较多；把 live-core 显式代入写入正文，可以让读者直接看到哪些项已有计算界，哪一项仍对应来源认证接口。一般 theorem 保留适用广度，实际 corollary 展示一个源程序可以实现的非空场景。

关于原语模型，集中说明两个相互独立的公共 oracle、所有 preparation/continuation/test 的预算，以及所有私有协议输入是经典的。SDK 派生表、durable rekey 和 production bootstrap 各自使用自己的 parent-secret 接口；一个清晰映射表足够，不需要在每项结果后重复范围说明。

理论与证据的主从关系也可以更直接：正文保留必要定义、证明和最关键的分离执行，artifact 收录详细 source pins、测试身份和构建记录。新 39 项有限核查、独立数学审查、此前 Rust CI 和符号证明分别报告其执行与结论范围。有限枚举支持接口与计数，不代替量子归约证明。

SkyBridge 已有独立的迁移、平台与实验研究线。对本篇 JoC 主论证，保留真正使用到的 transcript/admission/recovery-release 对应关系及来源说明即可；大量独立迁移实验由其自己的论文承担。本篇的稿件空间优先服务持续随机性来源和恢复证明。

## 对 JoC 方向的判断

JoC 官方范围包含密码协议、隐私、认证、密钥管理、量子密码学，以及实现和应用问题。[官方 aims and scope](https://link.springer.com/journal/145/aims-and-scope) 与本研究对象直接相符。当前工作已有明确原始机制、可陈述的理论结果和具体实现连接，具备按该方向组织投稿的研究实质。

影响当前论证说服力的具体事项是：主结论需要清晰展示 attribution 的真实状态；应用层的认证事件与原生总事件归约需要维持准确范围；比较段落需要让读者看到持久化来源模型相对于已有 vulnerable-set 方法的确切新增信息。它们都能对应到明确文本或证明任务。

进一步推广到任意 epoch、所有方向/消息、更多 primitive 或所有平台会形成额外成果。当前论文已经可以围绕已证明的有限计算接口和多 epoch 符号结果形成完整研究叙述；这些推广不自动成为本轮投稿内容的验收门槛。外部审稿最终评价的是新结果的意义、论证是否成立、假设是否清楚以及呈现是否可核查，不能从页数、测试数量或单一性能指标推算录用概率。

## 一手核查记录

本轮直接打开并定位了：SCKA Definition 3.2 / Theorem 3.3；Triple Ratchet Remark 4.3；Robust Channels 官方全文；JoC 官方 aims and scope；Session Handling 官方论文页；HMAC swapped-PRF 作者 ePrint；以及 Zhandry 的公开作者稿与正式出版版本。确认 MAC 的新增引用已统一为正式出版 Theorem 7 的 `C (Q+2)^3 / 2^256` 形式。不同文献的原语结果没有计作本项目原创结论。
