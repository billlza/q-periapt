# Journal of Cryptology：官方格式与政策核对

核对日期：2026-11-07；主要依据为 Springer 的 JoC 专页、该页链接的出版社政策、IACR 的 JoC 页面，以及实际下载的官方 LaTeX 包。未修改论文、未提交投稿、未查询 CI。

## 结论与采用方案

**JoC 没有在当前公开投稿指南中指定必须双栏、必须使用某个 class，或一个数值页数上限。** 这是对已核读页面的范围说明，不等于期刊接受任意长度。其初投明确偏好英文 LaTeX 单 PDF；单盲审稿，应保留真实作者信息。[S1]

本轮可采用官方 `sn-jnl.cls` 的单栏排版，并按 JoC 的引用规则选择数字、字母序、全作者的 bibliography。这是符合已查要求的工程选择，**不是宣称通用 Springer 模板是 JoC 唯一强制版式**。

## JoC 专页的明确要求与推荐

| 项目 | 已核实规则 | 性质 |
|---|---|---|
| 提交 | 英文；Editorial Manager `jcryptology` | 期刊明确指示 |
| 初投文件 | 单 PDF，LaTeX 或类似系统 | 强烈推荐 |
| 源文件 | 接收时需要 | 接收阶段要求 |
| 标题页 | 标题、作者、affiliations、通讯 email；ORCID 如有 | 期刊明确指示 |
| 摘要 | 150–250 词；定义缩写、避免未指定引用、少用数学符号 | 期刊明确指示 |
| Keywords | 5–10 个 | 期刊明确指示 |
| 引用与文献 | 方括号数字；按作者姓氏字母序排列后编号；完整书目信息、全部作者 | 期刊明确指示 |
| 匿名 | Single-blind | 保留作者信息 |
| 页数、栏数、专用 class | 本次核读未找到数值页限或指定格式 | 不新增门槛 |
| 数学环境 | 未指定特殊宏；官方模板提供 AMS/theorem 示例 | 采用可编译标准环境 |

本表来源：[S1]。Footnotes 宜少用；必要时连续编号。[S1]

## 官方模板：实际取得的文件

官方下载由 Springer Nature LaTeX author-support 页面链接获得，未猜测下载地址。[S6–S7]

- 包标识：**Version 3.1, December 2024**。
- 实际 URL：<https://cms-resources.apps.public.k8s.springernature.io/springer-cms/rest/v1/content/18782940/data/v12>。
- ZIP：901,814 bytes；SHA-256 `812e76dcaa9c28dc1bff1fb6065d51729b67d4ea140552a05088317414a3ecae`。
- 本地目录：`/workspace/scratch/646fb6c54bf4/work/joc_round3/templates/official_sn_template/sn-article-template/`。
- 主 class：该目录 `sn-jnl.cls`，SHA-256 `36d0c3273a59d48dc6a9c7b080dfa1ec50dc10229d8751568d1f2e490ffa5ecc`。
- 样稿与说明：`sn-article.tex`、`sn-article.pdf`、`user-manual.pdf`、`bst/`。
- class 自身的 `ProvidesClass` 仍写 `2019/11/18 v0.1`；这是包内实际 header，不能把包版本与该 header 混称。

原 ZIP、原 class、原 `.bst` 均保留。下载与逐文件 hash 在 `templates/template_download_manifest.json`。

### 本次实际验证的引用样式差异

用同一组 synthetic references、故意采用与姓氏字母序不同的 citation 顺序，实际运行 BibTeX 和 LaTeX：

| 配置 | 观察结果 | 决策 |
|---|---|---|
| 模板默认 `sn-mathphys-num` | 按引用顺序输出文献 | 不直接用于要求字母序的 JoC |
| 官方 `sn-basic,Numbered` | 数字方括号、字母序正确 | 但原 `.bst` 超过 3 作者会截断 |
| 原 class + 显式 natbib + 重命名 `joc-basic.bst` 派生样式 | 方括号数字、字母序、5 作者完整输出，定理/公式引用成功 | 可采用 |

最后一种配置的最小 probe：

```latex
\documentclass[pdflatex]{sn-jnl}
\usepackage{amsmath,amssymb,amsthm}
\usepackage[numbers,sort&compress]{natbib}
\bibliographystyle{joc-basic}
```

`joc-basic.bst` 是显式命名的本地派生文件：保留官方 `sn-basic.bst` 的排序，只移除 `format.names` 中 3-author 截断分支，并更改文件身份说明。它不是官方独立发布的 JoC `.bst`。原 `sn-jnl.cls` 完全不改；无 bibliography-style class option 时未发生缺宏。

Probe 路径：`templates/verification/joc-fullauthors-smoke.tex`；结果：`joc_fullauthors_verification.json`。三次 pdfLaTeX 加一次 BibTeX 全部 exit 0，生成 bibliography 顺序 `alpha, many, middle, zulu`，five-author 条目完整显示五个姓氏，无 `et al`。

这是模板配置验证，未声称已验证主稿。主 agent 后续对实际论文编译和检查。

### 工作源与投稿源

官方模板技术注释要求提交一个 `.tex`，不以 `\input` 拆分投稿源。[S7] 本轮采用“模块化工作源 + 生成单文件 `joc-submission.tex`”的安排；图片和 bibliography 配套文件保持独立。该安排落实模板技术建议，不禁止研究过程中保留模块化源文件，也不把源文件接收阶段的说明误写成初投必须上传全部源。

## Editorial scope 与声明

JoC 的范围包含现代信息安全的理论、实现与应用，列有 cryptographic protocols、key management、quantum cryptography；IACR 也确认接受完整研究论文及短文等形式。项目方向属于该范围，具体创新性与录用判断仍由论文内容决定。[S2–S3]

| 项目 | 当前官方依据 | 本轮排版安排 |
|---|---|---|
| 利益冲突、资助、作者贡献 | Springer 的声明政策；JoC 另有 competing-interest policy | 用真实信息准备 Declarations；不代填事实 [S4–S5] |
| 数据、代码 | 出版社要求数据可用性说明；JoC 专页未另列具体 repository 或 code deposit 规则 | 写实际访问方式与版本，不声称必须某平台或公开全部数据 [S4,S10] |
| Preprint | 可发布；提交时披露相关信息，正式发表后更新链接 | 可保留 ePrint 等预印本路线 [S4] |
| IACR conflicts | IACR 的 JoC 页面明确引入其 conflicts policy | 投稿时按真实关系填写 [S3,S11] |

**AI：说明实际辅助用途，明确作者责任。** [S8] 本次未发现 JoC 单独指定声明标题或固定措辞。只准备事实性草稿：填写实际任务和可确认的工具信息；不预填尚未发生的人工核验或作者责任确认。投稿前由作者确认。

作者元数据同样按事实填写。通讯邮箱、共同作者与最终 affiliation/责任信息如未确认，应在交接中列明，不能为凑齐模板虚构。排稿不等于正式投稿。

## 来源索引

- **S1 — JoC Submission guidelines**：[官方页面](https://link.springer.com/journal/145/submission-guidelines)。
- **S2 — JoC Aims and scope**：[官方页面](https://link.springer.com/journal/145/aims-and-scope)。
- **S3 — IACR Journal of Cryptology**：[官方页面](https://www.iacr.org/jofc/)。
- **S4 — Springer Journal policies**：[官方页面](https://link.springer.com/brands/springer/journal-policies)，含 authorship、declarations、preprint、data policy。
- **S5 — JoC Ethics & disclosures**：[官方页面](https://link.springer.com/journal/145/ethics-and-disclosures)。
- **S6 — Springer Nature LaTeX author support / download**：[官方页面](https://www.springernature.com/gp/authors/campaigns/latex-author-support/see-where-our-services-will-take-you/18782940)。
- **S7 — Publisher-authored Overleaf template**：[官方模板](https://www.overleaf.com/latex/templates/springer-nature-latex-template/gsvvftmrppwq)。
- **S8 — AI use in manuscript preparation**：[官方政策](https://www.springernature.com/gp/policies/editorial-policies/ai-manuscript-preparation)。
- **S9 — AI use in research practice**：[官方关联政策](https://www.springernature.com/gp/policies/editorial-policies/using-ai-in-research)。
- **S10 — Data availability statements**：[官方政策](https://www.springernature.com/gp/authors/research-data-policy/data-availability-statements)。
- **S11 — IACR Conflicts policy**：[官方 PDF](https://www.iacr.org/docs/conflicts.pdf)。

对应浏览 source refs、规则分类、实际下载文件与 probe 路径保存在 `venue_format_audit.json`。截至本次读取，未发现 JoC 专属 class 下载要求；通用模板的 production-ready 选项不能自动提升为 JoC 的硬性规则。
