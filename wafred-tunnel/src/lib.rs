//! WAFred tunnel.
//!
//! Two halves in one crate:
//!
//! * the **edge side** ([`server`], [`registry`]) — a TLS listener on the data
//!   plane that accepts connector sessions and bridges each tunnel target to a
//!   loopback port pingora can dial as an ordinary origin;
//! * the **connector** (`connector` feature, [`client`]) — the binary that runs
//!   inside the private network, pairs with the control plane and dials the
//!   edges outbound.
//!
//! The edge half is compiled into the agent and the all-in-one binary; the
//! connector half is only in the `wafred-tunnel` binary, so an agent build does
//! not link tonic or clap for it.

pub mod cert;
#[cfg(feature = "connector")]
pub mod client;
pub mod protocol;
pub mod registry;
pub mod runtime;
pub mod server;
pub mod session;
pub mod socks5;
pub mod token;
pub mod verify;

pub use cert::TunnelCertificate;
pub use protocol::{ControlFrame, ErrorCode, TunnelSettings};
pub use registry::{TunnelPolicy, TunnelRegistry};
pub use runtime::{
    TunnelRuntime, install_runtime, installed_registry, runtime,
};
pub use server::TunnelAcceptor;
pub use session::{Session, SessionReport};
pub use socks5::Socks5Proxy;
