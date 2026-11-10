/**
 * @name Rust database quality metrics
 * @description Emits fail-closed extraction, macro, format-argument, and consistency metrics.
 * @kind table
 * @id qperiapt/rust-quality/metrics
 */

import rust
import codeql.files.FileSystem
import codeql.rust.Diagnostics
import codeql.rust.dataflow.DataFlow
private import codeql.rust.internal.AstConsistency as AstConsistency
private import codeql.rust.internal.PathResolutionConsistency as PathResolutionConsistency
private import codeql.rust.internal.typeinference.TypeInferenceConsistency as TypeInferenceConsistency
private import codeql.rust.controlflow.internal.CfgConsistency as CfgConsistency
private import codeql.rust.dataflow.internal.SsaImpl::Consistency as SsaConsistency
private import codeql.rust.dataflow.internal.DataFlowConsistency as DataFlowConsistency

private int metric(string name) {
  name = "extraction_errors" and result = count(ExtractionError error)
  or
  name = "extraction_warnings" and result = count(ExtractionWarning warning)
  or
  name = "extracted_files" and
  result = count(ExtractedFile file | exists(file.getRelativePath()))
  or
  name = "successfully_extracted_files" and
  result = count(SuccessfullyExtractedFile file | exists(file.getRelativePath()))
  or
  name = "unextracted_elements" and result = count(Unextracted element)
  or
  name = "source_macro_calls" and result = count(MacroCall call | call.fromSource())
  or
  name = "unresolved_source_macro_calls" and
  result = count(MacroCall call | call.fromSource() and not call.hasMacroCallExpansion())
  or
  name = "source_format_args" and
  result = count(FormatArgsArg argument | argument.fromSource())
  or
  name = "source_format_args_without_expr" and
  result = count(FormatArgsArg argument | argument.fromSource() and not argument.hasExpr())
  or
  name = "source_format_args_without_dataflow_node" and
  result =
    count(FormatArgsArg argument |
      argument.fromSource() and
      exists(argument.getExpr()) and
      not exists(DataFlow::Node node | node.asExpr() = argument.getExpr())
    )
  or
  name = "ast_inconsistencies" and
  result = sum(string type | | AstConsistency::getAstInconsistencyCounts(type))
  or
  name = "path_resolution_inconsistencies" and
  result =
    sum(string type | | PathResolutionConsistency::getPathResolutionInconsistencyCounts(type))
  or
  name = "path_multiple_path_resolutions" and
  result = PathResolutionConsistency::getPathResolutionInconsistencyCounts(
    "Multiple path resolutions"
  )
  or
  name = "path_multiple_resolved_targets" and
  result = PathResolutionConsistency::getPathResolutionInconsistencyCounts(
    "Multiple resolved targets"
  )
  or
  name = "path_multiple_record_fields" and
  result = PathResolutionConsistency::getPathResolutionInconsistencyCounts(
    "Multiple record fields"
  )
  or
  name = "path_multiple_tuple_fields" and
  result = PathResolutionConsistency::getPathResolutionInconsistencyCounts(
    "Multiple tuple fields"
  )
  or
  name = "path_multiple_canonical_paths" and
  result = PathResolutionConsistency::getPathResolutionInconsistencyCounts(
    "Multiple canonical paths"
  )
  or
  name = "type_inference_inconsistencies" and
  result =
    sum(string type | | TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(type))
  or
  name = "type_missing_parameter_id" and
  result = TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(
    "Missing type parameter ID"
  )
  or
  name = "type_nonfunctional_parameter_id" and
  result = TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(
    "Non-functional type parameter ID"
  )
  or
  name = "type_noninjective_parameter_id" and
  result = TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(
    "Non-injective type parameter ID"
  )
  or
  name = "type_ill_formed_mention" and
  result = TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(
    "Ill-formed type mention"
  )
  or
  name = "type_nonunique_certain_information" and
  result = TypeInferenceConsistency::getTypeInferenceInconsistencyCounts(
    "Non-unique certain type information"
  )
  or
  name = "cfg_inconsistencies" and
  result = sum(string type | | CfgConsistency::getCfgInconsistencyCounts(type))
  or
  name = "ssa_inconsistencies" and
  result = sum(string type | | SsaConsistency::getInconsistencyCounts(type))
  or
  name = "dataflow_inconsistencies" and
  result = sum(string type | | DataFlowConsistency::getInconsistencyCounts(type))
}

from string name, int value
where value = metric(name)
select name, value
