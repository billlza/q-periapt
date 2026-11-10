/**
 * @name Rust source macro coverage by compilation target
 * @description Retains every macro entity and distinguishes compiler-only export metadata.
 * @kind table
 * @id qperiapt/rust-quality/macro-calls
 */
import rust

private predicate isExportNameValue(MacroCall call) {
  exists(KeyValueMeta meta |
    not meta.getPath().hasQualifier() and meta.getPath().getText() = "export_name" and
    meta.getExpr().(MacroExpr).getMacroCall() = call
  ) and
  not exists(call.getACfgNode())
}

private string context(MacroCall call) {
  isExportNameValue(call) and result = "export_name"
  or
  not isExportNameValue(call) and result = "code"
}

from MacroCall call, string expansion
where
  call.fromSource() and
  (
    call.hasMacroCallExpansion() and expansion = "expanded"
    or
    not call.hasMacroCallExpansion() and expansion = "unresolved"
  )
select call.getFile().getRelativePath(), call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(), call.toString(), expansion, context(call), call
