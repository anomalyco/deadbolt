//! The control protocol between the CLI and the daemon. Its messages live in
//! [`deadbolt_proto::daemon`], the one schema every client and the daemon share.

pub use deadbolt_proto::daemon::*;
