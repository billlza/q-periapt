/**
 * @name Unresolved Rust source macros
 * @description Emits the source path and location for every macro invocation without an expansion.
 * @kind table
 * @id qperiapt/rust-quality/unresolved-macros
 */

import rust

from MacroCall call
where call.fromSource() and not call.hasMacroCallExpansion()
select
  call.getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(),
  call.toString()
