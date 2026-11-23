// SPDX-FileCopyrightText: 2026 OpenXPlay.org
// SPDX-License-Identifier: AGPL-3.0-only

//! Reuses an access point owned by another component (for example `com.tbwj.gateway`)
//! instead of building one.
//!
//! The manager only observes the interface: it never brings the AP up, never rewrites
//! its credentials and never tears it down. `close` is deliberately a no-op so a relay
//! restart cannot delete an AP that another process keeps alive.

use crate::network::wireless_hotspot_manager::{WirelessHotspotInfo, WirelessHotspotManager};
use crate::Result;
use carplay_iap2::Iap2WirelessSecurity;
use std::{net::Ipv4Addr, path::PathBuf, process::Command, time::Duration};

/// True when the interface exists and currently runs as an access point.
pub fn interface_in_ap_mode(interface: &str) -> bool {
    Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .is_some_and(|out| out.lines().any(|l| l.trim() == "type AP"))
}

/// Maps `hotspotSecurity` values onto the iAP2 wireless security codes.
pub fn security_from_setting(value: &str) -> Iap2WirelessSecurity {
    match value {
        "open" => Iap2WirelessSecurity::None,
        "wpa3" => Iap2WirelessSecurity::Wpa3Only,
        "wpa3-transition" => Iap2WirelessSecurity::Wpa3Transition,
        _ => Iap2WirelessSecurity::WpaWpa2,
    }
}

/// Reads an AP that someone else keeps alive.
pub struct ExternalApManager {
    interface: String,
    passphrase: String,
    security: Iap2WirelessSecurity,
    net_root: PathBuf,
}

impl ExternalApManager {
    pub fn new(
        interface: String,
        passphrase: String,
        security: Iap2WirelessSecurity,
        net_root: PathBuf,
    ) -> Self {
        Self {
            interface,
            passphrase,
            security,
            net_root,
        }
    }

    fn iw_info(&self) -> (Option<String>, Option<u8>) {
        let out = Command::new("iw")
            .args(["dev", &self.interface, "info"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let mut ssid = None;
        let mut channel = None;
        for line in out.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("ssid ") {
                ssid = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("channel ") {
                channel = v.split_whitespace().next().and_then(|n| n.parse::<u8>().ok());
            }
        }
        (ssid, channel)
    }

    fn mode(&self) -> Option<String> {
        let out = Command::new("iw")
            .args(["dev", &self.interface, "info"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())?;
        out.lines()
            .find_map(|l| l.trim().strip_prefix("type ").map(|v| v.trim().to_string()))
    }

    fn mac(&self) -> Option<String> {
        std::fs::read_to_string(self.net_root.join(&self.interface).join("address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn ipv4(&self) -> Option<Ipv4Addr> {
        let out = Command::new("ip")
            .args(["-4", "-o", "addr", "show", "dev", &self.interface])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .find_map(|w| w.split('/').next()?.parse::<Ipv4Addr>().ok())
    }
}

impl WirelessHotspotManager for ExternalApManager {
    fn start(&self, _timeout: Duration) -> Result<WirelessHotspotInfo> {
        if !self.net_root.join(&self.interface).join("address").exists() {
            return Err(std::io::Error::other(format!(
                "external AP interface {} is absent",
                self.interface
            ))
            .into());
        }
        let (ssid, channel) = self.iw_info();
        let ssid = ssid.ok_or_else(|| {
            std::io::Error::other(format!("external AP {} has no SSID", self.interface))
        })?;
        let mac = self.mac();
        Ok(WirelessHotspotInfo {
            ssid,
            passphrase: self.passphrase.clone(),
            channel: channel.unwrap_or(0),
            security: self.security,
            host_address: self.ipv4(),
            bssid: mac.clone(),
            access_point_bssid: mac,
            interface_name: Some(self.interface.clone()),
        })
    }

    fn validate_ready(&self) -> Result<()> {
        match self.mode().as_deref() {
            Some("AP") => Ok(()),
            other => Err(std::io::Error::other(format!(
                "external AP interface {} is not in AP mode ({other:?})",
                self.interface
            ))
            .into()),
        }
    }

    fn on_car_play_confirmed(&self) -> Result<()> {
        Ok(())
    }

    /// The AP belongs to another owner: closing this manager leaves it running.
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
