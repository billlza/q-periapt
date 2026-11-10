# JoC manuscript 构建与投稿导出：窄范围独立审读

日期：2026-11-07。结论：**PASS — 在当前声明的 workflow 调用链下，未发现阻塞性路径、CLI、正则转义或失败后上传旧 PDF 的问题。**

审读对象为 `q-periapt-paper` 工作区的 `.github/workflows/joc-manuscript.yml`、`paper/continuity/Makefile`、`check_build.py`、`export_submission.py`。为核对调用，另只读了 `flatten_manuscript.py`、两个保留的 finite-model 脚本及当前 `main.tex` 的摘要／关键词语法，并与 `q-periapt-ci` 原有 workflow pins 比对。本次未改这些文件，未新增测试，未重新构建、运行模型或审查论文数学内容。

## 1. CLI、工作目录与输出路径

| workflow／Makefile 调用 | 实际接口与输出 | 结论 |
| --- | --- | --- |
| `make -B -C paper/continuity check` | `check` 为 phony target，先生成 `joc-submission.tex`、构建图和论文，再调用 `python3 check_build.py`。`-C` 将相对路径固定到论文目录。 | 对齐。 |
| `python3 flatten_manuscript.py` | 无需 CLI 参数；按脚本目录读取模块，写 `joc-submission.tex` 与 `flatten_manifest.json`。 | 对齐。 |
| `latexmk ... -outdir=build joc-submission.tex` | 主输出为 `build/joc-submission.pdf`／`.log`；成功后复制到 `continuity.pdf`。 | 与检查器及上传路径对齐。 |
| 图的 `latexmk ... -outdir=../build/figures confirmation-cut.tex` | 在 `figures/` 中执行；输出位于 `build/figures/confirmation-cut.pdf`，再复制到 `figures/confirmation-cut.pdf`。 | 相对路径正确。 |
| `python3 check_build.py` | 无需参数；读取主 log、两个 PDF、flatten manifest 与作者元数据；写 `build/build-check.json`。 | 对齐。 |
| `python3 check_exposure.py --output results.json` | 脚本确实提供 `--output`；workflow 已进入 `build/finite-model/`。 | 输出为上传项 `build/finite-model/results.json`。 |
| `python3 review_exposure.py` | 通过脚本自身目录导入同目录 checker，并在该目录写 `review_results.json`。workflow 同时复制了两个脚本。 | 输出为上传项 `build/finite-model/review_results.json`。 |
| `python3 export_submission.py --output build/joc-source.zip` | `--output` 为必需参数；读取通过的 build check，核对生成 TeX 的 SHA-256，再打包七项声明依赖与 README、SHA256SUMS。 | CLI 和 ZIP 路径对齐；七项依赖在审读快照中均存在。 |

## 2. 失败传播与产物上传

`Makefile` 没有忽略错误的 recipe 前缀，workflow 也没有 `continue-on-error`。图或主文的 `latexmk -halt-on-error` 失败会停止对应 recipe，后面的 `cp` 不执行。`check_build.py` 对已收集的失败返回非零；文件缺失、非法 JSON、解析工具失败等异常同样会使该步骤失败。两个模型脚本在不满足断言／独立期望时失败；export 的输入检查或写 ZIP 失败也会传播。

主产物步骤 **Upload manuscript and source** 没有覆盖默认成功条件，因此只在前面所有步骤成功后运行。它上传 PDF、源码 ZIP、构建与有限模型记录。已存在于工作区的旧 `continuity.pdf` 或旧 ZIP，不会因为编译、检查或打包失败而被这一步继续上传。

唯一的 `if: always()` 是 **Preserve build diagnostics**。其路径仅包含主构建的 `*.log`、`*.blg`、`build-check.json`、`source-commit.txt`，**没有 PDF 或 ZIP**。因此失败后仍可能上传诊断记录，但不会将论文旧产物发布为成功输出。

源版本检查使用与 checkout 相同的 `github.event.pull_request.head.sha || github.sha`，并将实际 `git rev-parse HEAD` 写入 `build/source-commit.txt`。这两处表达式一致。

## 3. Python 正则与当前输入形态

已逐项静态核对 raw-string 的反斜杠层次：

- `Overfull` 检查使用字面反斜杠后接 `[hv]box`，匹配 TeX 的 `Overfull \hbox`／`Overfull \vbox`，并非把 `\h` 当成未知正则转义。
- 摘要模式匹配字面 `\abstract{...}` 及其后的 `\keywords`；`re.S` 允许摘要跨行。当前 `main.tex` 正是这一相邻宏形态，摘要为普通英文文本。
- 关键词模式匹配当前平坦的逗号分隔列表；当前列表没有嵌套花括号。词数为摘要文本的空白切分计数，关键词数为逗号切分计数，适用于本稿当前形态。
- 页数模式 `^Pages:\s+(\d+)` 配合多行模式，针对 `pdfinfo` 的 `Pages:` 字段。
- 错误、未定义引用／交叉引用重跑和重复标签模式的转义没有 Python 语法问题；首行 `!` 使用多行锚点。

这是一项当前输入与检查代码的静态核对，不把这些有限正则描述为一般 LaTeX 语法解析器。

## 4. GitHub action pins

| action | 新 workflow 的固定 SHA | 原仓库比对 |
| --- | --- | --- |
| `actions/checkout` | `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` | 与 `q-periapt-ci/.github/workflows/ci.yml`、`continuity-proof-environment.yml` 等已读取配置一致。 |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | 与上述原配置一致；成功产物与诊断上传使用同一 SHA。 |

这里确认的是项目固定版本的一致性，不另外推断 release tag 或 action 上游审计状态。

## 5. 独立导出时的依赖身份：补充修订已核读

初次审读指出，独立 export CLI 只复核生成 TeX 的摘要；当前 workflow 顺序已满足其调用契约。随后根代理补充了依赖身份核对。本次已再次只读检查该改动：`check_build.py` 的 `build_inputs` 包含全部已展开模块、生成 TeX、bibliography、class／两份 style、figure 及作者元数据；`export_submission.py` 在读包内容前逐项核对这些 SHA-256，不匹配即非零退出。缺少 `build_inputs` 的旧检查记录同样不能通过该代码路径。

因此，初次发现的“在检查之后修改其他依赖，再单独 export”的范围缺口已经闭合。workflow、CLI 及输出路径保持不变。本次补充审查未新增或重跑任何测试。

## 6. 审读快照

本记录按工作区实际文件字节审读；以下 SHA-256 精确绑定所读内容，其中两个 Python 文件包含上述补充修订。

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `.github/workflows/joc-manuscript.yml` | 3055 | `927c30b54981a86ffc2ffae373883585b7644208f983414cc3a9ec58f0a0be13` |
| `paper/continuity/Makefile` | 1025 | `e893ad9b0cad9948ac1579ef487aa552beff241e450f5e71ba5738638851ea7c` |
| `paper/continuity/check_build.py` | 3792 | `5b5fcb183e847d6df67210b9e6f9c802a8e6bb04c3c97228d267544b0a943c86` |
| `paper/continuity/export_submission.py` | 2444 | `fd76730d9abb02e4d0daab6c5cba654ed1385f5a3ef73516f5e9289615edfcf3` |

本记录的通过结论是上述静态构建链审读结果；实际 GitHub 运行状态由对应 run 的结果记录。
