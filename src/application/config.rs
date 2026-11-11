use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuanceTimingConfig {
    pub roa_valid_weeks: u32,
    pub aspa_valid_weeks: u32,
    pub sispi_valid_weeks: u32,
    pub toa_valid_weeks: u32,
    /// Operator-selected interval for the draft's periodic TOA review.
    pub toa_review_days: u32,
    pub publish_next_hours: u32,
    pub publish_next_jitter_hours: u32,
    pub publish_hours_before_next: u32,
}

impl Default for IssuanceTimingConfig {
    fn default() -> Self {
        Self {
            roa_valid_weeks: 52,
            aspa_valid_weeks: 52,
            sispi_valid_weeks: 52,
            toa_valid_weeks: 52,
            toa_review_days: 90,
            publish_next_hours: 24,
            publish_next_jitter_hours: 4,
            publish_hours_before_next: 8,
        }
    }
}

impl IssuanceTimingConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value, maximum) in [
            ("roa_valid_weeks", self.roa_valid_weeks, 520),
            ("aspa_valid_weeks", self.aspa_valid_weeks, 520),
            ("toa_valid_weeks", self.toa_valid_weeks, 520),
            ("sispi_valid_weeks", self.sispi_valid_weeks, 520),
            ("toa_review_days", self.toa_review_days, 3650),
            ("publish_next_hours", self.publish_next_hours, 87600),
        ] {
            anyhow::ensure!(
                value <= maximum,
                "{name} exceeds implementation limit {maximum}"
            );
        }
        anyhow::ensure!(self.roa_valid_weeks > 0, "roa_valid_weeks must be positive");
        anyhow::ensure!(
            self.aspa_valid_weeks > 0,
            "aspa_valid_weeks must be positive"
        );
        anyhow::ensure!(
            self.sispi_valid_weeks > 0,
            "sispi_valid_weeks must be positive"
        );
        anyhow::ensure!(self.toa_valid_weeks > 0, "toa_valid_weeks must be positive");
        anyhow::ensure!(self.toa_review_days > 0, "toa_review_days must be positive");
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
#[serde(default, deny_unknown_fields)]
pub struct CaConfig {
    pub name: String,
    pub repository_uri: String,
    /// Public rsync URI where relying parties can fetch this CA certificate.
    pub certificate_uri: String,
    /// Optional RRDP notification URI advertised by newly issued development CA certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rrdp_notification_uri: Option<String>,
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
            rrdp_notification_uri: None,
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

impl CaConfig {
    /// TOML uses the same schema as persisted ca.toml; omitted fields use defaults.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        self.timing.validate()?;
        if let Some(value) = &self.rrdp_notification_uri {
            let _: rpki::uri::Https = value.parse()?;
        }
        ensure!(
            !self.name.trim().is_empty() && !self.name.chars().any(char::is_control),
            "CA name must be nonempty and contain no control characters"
        );
        ensure!(
            (1..=36500).contains(&self.development_ca_validity_days),
            "development_ca_validity_days must be between 1 and 36500"
        );
        ensure!(
            (1..=36500).contains(&self.ca_renew_before_days),
            "ca_renew_before_days must be between 1 and 36500"
        );
        let base: rpki::uri::Rsync =
            format!("{}/", self.repository_uri.trim_end_matches('/')).parse()?;
        ensure!(
            !base.module_name().is_empty(),
            "repository URI requires a module"
        );
        if !self.certificate_uri.is_empty() {
            let uri: rpki::uri::Rsync = self.certificate_uri.parse()?;
            ensure!(
                uri.path().ends_with(".cer"),
                "certificate_uri must identify a .cer file"
            );
        }
        for prefix in &self.development_resources {
            ensure!(
                prefix.addr() == prefix.network(),
                "resource prefix has host bits: {prefix}"
            );
        }
        let ips: std::collections::BTreeSet<_> = self.development_resources.iter().collect();
        let asns: std::collections::BTreeSet<_> = self.development_asns.iter().collect();
        ensure!(
            ips.len() == self.development_resources.len(),
            "duplicate IP resources"
        );
        ensure!(
            asns.len() == self.development_asns.len(),
            "duplicate ASN resources"
        );
        Ok(())
    }

    pub fn validate_development(&self) -> anyhow::Result<()> {
        self.validate()?;
        anyhow::ensure!(
            self.ca_renew_before_days < self.development_ca_validity_days,
            "ca_renew_before_days must be less than development_ca_validity_days"
        );
        anyhow::ensure!(
            !self.development_resources.is_empty() || !self.development_asns.is_empty(),
            "development CA needs IP or ASN resources"
        );
        anyhow::ensure!(
            u64::from(self.timing.publish_next_hours)
                + u64::from(self.timing.publish_next_jitter_hours)
                < u64::from(self.development_ca_validity_days) * 24,
            "publication window must be shorter than development CA lifetime"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/application/config.rs"]
mod tests;
