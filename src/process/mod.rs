#[cfg(not(feature = "edge"))]
mod auto_restart;
mod common;

#[cfg(not(feature = "edge"))]
pub use auto_restart::*;
pub use common::*;
