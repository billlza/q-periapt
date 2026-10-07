/**
 * @name Successfully extracted Rust source paths
 * @description Emits every source-relative Rust file that has no extraction diagnostic.
 * @kind table
 * @id qperiapt/rust-quality/extracted-paths
 */

import codeql.files.FileSystem

from SuccessfullyExtractedFile file
where exists(file.getRelativePath())
select file.getRelativePath()
