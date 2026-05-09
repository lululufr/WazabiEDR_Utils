//! Plugin manifest schema.
//!
//! This struct MUST stay byte-identical to
//! `WazabiEDR_Agent::plugin::manifest::PluginManifest`. We deliberately
//! duplicate it here rather than depending on the agent crate so the
//! enrolment tool stays small (no kernel-event types pulled in
//! transitively) and the two crates can be built independently. If you
//! add a field on either side, mirror it on the other and add a test
//! that round-trips a manifest through both.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub name: String,
    pub vendor: String,
    pub expected_path: String,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub expected_signer: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub enrolled_at: Option<String>,
}
