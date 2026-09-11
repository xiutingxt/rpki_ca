use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceTimingConfig {
    pub roa_valid_weeks: u32,
    pub aspa_valid_weeks: u32,
    pub publish_next_hours: u32,
    pub publish_next_jitter_hours: u32,
    pub publish_hours_before_next: u32,
}

impl Default for IssuanceTimingConfig {
    fn default() -> Self {
        Self {
            roa_valid_weeks: 52,
            aspa_valid_weeks: 52,
            publish_next_hours: 24,
            publish_next_jitter_hours: 4,
            publish_hours_before_next: 8,
        }
    }
}

impl IssuanceTimingConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.roa_valid_weeks > 0, "roa_valid_weeks must be positive");
        anyhow::ensure!(
            self.aspa_valid_weeks > 0,
            "aspa_valid_weeks must be positive"
        );
        anyhow::ensure!(
            self.publish_next_hours >= 2,
            "publish_next_hours must be at least 2"
        );
        anyhow::ensure!(
            self.publish_next_jitter_hours <= self.publish_next_hours / 2,
            "publish_next_jitter_hours must not exceed half of publish_next_hours"
        );
        anyhow::ensure!(
            self.publish_hours_before_next > 0,
            "publish_hours_before_next must be positive"
        );
        anyhow::ensure!(
            self.publish_hours_before_next < self.publish_next_hours,
            "publish_hours_before_next must be less than publish_next_hours"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub name: String,
    pub repository_uri: String,
    /// Public rsync URI where relying parties can fetch this CA certificate.
    pub certificate_uri: String,
    pub development_ca_validity_days: u32,
    /// Report that renewal is required this many days before CA expiry.
    pub ca_renew_before_days: u32,
    pub timing: IssuanceTimingConfig,
    /// Only used when creating a development trust anchor. Imported RCs use
    /// the resources embedded in their certificate.
    #[serde(default = "default_development_resources")]
    pub development_resources: Vec<IpNet>,
    #[serde(default)]
    pub development_asns: Vec<u32>,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            name: "development-ca".into(),
            repository_uri: "rsync://localhost/rpki/".into(),
            // Generated from the development key by CaManager::init. Imports
            // must provide the URI assigned by the issuing parent CA.
            certificate_uri: String::new(),
            development_ca_validity_days: 365,
            ca_renew_before_days: 30,
            timing: IssuanceTimingConfig::default(),
            development_resources: default_development_resources(),
            development_asns: Vec::new(),
        }
    }
}

fn default_development_resources() -> Vec<IpNet> {
    vec![
        "192.0.2.0/24".parse().expect("valid built-in prefix"),
        "2001:db8::/48".parse().expect("valid built-in prefix"),
    ]
}

#[cfg(test)]
#[path = "../../tests/unit/application/config.rs"]
mod tests;
