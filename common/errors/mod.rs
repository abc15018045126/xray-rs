pub mod errors;
pub mod feature_errors;
pub mod multi_error;
#[cfg(test)]
pub mod errors_test;

pub use errors::{
    Error, ErrorDetail, Result, cause, get_severity, log_debug, log_debug_inner, log_error,
    log_error_inner, log_info, log_info_inner, log_warning, log_warning_inner,
    new as new_error_detail, new_error,
};
pub use feature_errors::{
    missing_feature, print_deprecated_feature_warning,
    print_non_removal_deprecated_feature_warning, print_removed_feature_error,
};
pub use multi_error::{MultiError, all_equal, combine};
