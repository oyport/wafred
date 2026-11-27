// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Version banner shared by the `pingwaf`/`pingap` binaries and the
//! agent-only `wafred-agent` build.
//!
//! Both binaries answer `--version` themselves (the WAFred CLI intercepts the
//! flag before clap), so the banner lives here instead of in one bin's crate
//! root. The `edge` marker is compile-time: it is how an operator can tell an
//! agent-only install from the all-in-one build without inspecting the file
//! size, and install.sh's smoke test relies on `--version` succeeding either
//! way.

use std::sync::LazyLock;

/// The commit this binary was built from, or "unknown" when the tree had no
/// git metadata (a source export or a crates.io tarball; see build.rs).
pub(crate) fn git_hash() -> &'static str {
    match env!("VERGEN_GIT_SHA") {
        "VERGEN_IDEMPOTENT_OUTPUT" => "unknown",
        sha => sha,
    }
}

pub(crate) static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} ({}, tls={}{})",
        env!("CARGO_PKG_VERSION"),
        git_hash(),
        pingap_certificate::TLS_BACKEND,
        if cfg!(feature = "edge") { ", edge" } else { "" },
    )
});

/// The version banner: crate version, build commit, TLS backend and whether
/// this is the agent-only (`edge`) build. Shared by `--version` and the
/// WAFred-mode CLI, which answers the flag itself.
pub(crate) fn version_banner() -> &'static str {
    &LONG_VERSION
}
