//! Independent authority and user-traffic capabilities of a mesh participant.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlMode {
    Main,
    Child,
}

/// User traffic capability. Entry accepts devices, relay forwards mesh traffic, and off carries only control traffic.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    // Existing assignments without this field were client entry points.
    #[default]
    Entry,
    Relay,
    Off,
}
impl TrafficMode {
    pub fn accepts_devices(self) -> bool {
        self == Self::Entry
    }
    pub fn carries_user_traffic(self) -> bool {
        self != Self::Off
    }
}
