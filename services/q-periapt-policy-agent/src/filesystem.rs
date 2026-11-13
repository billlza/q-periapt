//! Shared private-file boundary; implementation and its direct tests live in host-store.

#[cfg(all(test, unix))]
pub(crate) use q_periapt_host_store::filesystem::PrivateFileError;
#[cfg(unix)]
pub(crate) use q_periapt_host_store::filesystem::{
    copy_to_anonymous_scratch, open_private_parent, OwnedPrivateDirectory,
};
pub(crate) use q_periapt_host_store::filesystem::{
    open_private_file, provision_private_file, refuse_unclean_foreign_redb,
};
