pub use super::Error;
use super::errors::log_warning;

pub fn print_non_removal_deprecated_feature_warning(source_feature: &str, target_feature: &str) {
    log_warning(format!(
        "The feature {} is deprecated, not recommended for using and might be removed. Please migrate to {} as soon as possible.",
        source_feature, target_feature
    ));
}

pub fn print_deprecated_feature_warning(feature: &str, migrate_feature: &str) {
    if !migrate_feature.is_empty() {
        log_warning(format!(
            "This feature {} is deprecated, will be removed soon and being migrated to {}. Please update your config(s) according to release note and documentation before removal.",
            feature, migrate_feature
        ));
    } else {
        log_warning(format!(
            "This feature {} is deprecated and will be removed soon. Please update your config(s) according to release note and documentation before removal.",
            feature
        ));
    }
}

pub fn print_removed_feature_error(feature: &str, migrate_feature: &str) -> Error {
    if !migrate_feature.is_empty() {
        Error::Config(format!(
            "The feature {} has been removed and migrated to {}. Please update your config(s) according to release note and documentation.",
            feature, migrate_feature
        ))
    } else {
        Error::Config(format!(
            "The feature {} has been removed. Please update your config(s) according to release note and documentation.",
            feature
        ))
    }
}

pub fn missing_feature(name: &str) -> Error {
    Error::Config(format!("Feature '{}' not found", name))
}
