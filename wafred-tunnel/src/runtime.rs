//! The process-wide tunnel runtime.
//!
//! Three places need the same registry, and they live in different crates: the
//! data-plane startup creates it, the configuration generator asks it for a
//! bridge address, and the heartbeat reports what it holds. A single install
//! point (here) keeps that from becoming a parameter threaded through every
//! layer, and matches how the agent instance itself is a process global.
//!
//! Installed at most once. An agent that does not enable the tunnel listener
//! never installs one, and every reader degrades to "no tunnels".

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use crate::registry::TunnelRegistry;

/// What the data plane installed.
#[derive(Debug)]
pub struct TunnelRuntime {
    pub registry: Arc<TunnelRegistry>,
    /// The address the listener actually bound, `None` when it is not running.
    pub listener_addr: Option<SocketAddr>,
    /// Lower-case hex SHA-256 of the certificate leaf; empty without a
    /// listener.
    pub cert_fingerprint: String,
    /// Why a configured listener is not running. `None` when it is active or
    /// when no listener was configured at all.
    pub listener_error: Option<String>,
}

static RUNTIME: OnceLock<TunnelRuntime> = OnceLock::new();

/// Installs the runtime. Returns false when one was already installed.
pub fn install_runtime(runtime: TunnelRuntime) -> bool {
    RUNTIME.set(runtime).is_ok()
}

/// The installed runtime, when this process runs a tunnel listener.
pub fn runtime() -> Option<&'static TunnelRuntime> {
    RUNTIME.get()
}

/// The installed registry, when there is one.
///
/// Named `installed_registry` rather than `registry` because the crate also
/// exposes the `registry` module, and a function of the same name in the same
/// namespace would be shadowed by it.
pub fn installed_registry() -> Option<Arc<TunnelRegistry>> {
    runtime().map(|runtime| Arc::clone(&runtime.registry))
}
