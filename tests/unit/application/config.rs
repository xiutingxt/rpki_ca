use super::*;

#[test]
fn partial_configuration_defaults_and_unknown_fields() {
    let config: CaConfig = toml::from_str("name = 'lab'\n[timing]\nroa_valid_weeks = 8\n").unwrap();
    config.validate_development().unwrap();
    assert_eq!(config.timing.aspa_valid_weeks, 52);
    assert_eq!(config.timing.roa_valid_weeks, 8);
    assert!(toml::from_str::<CaConfig>("nmae = 'typo'").is_err());
    assert!(toml::from_str::<CaConfig>("[timing]\nroa_valid_week = 1").is_err());
    let example: CaConfig = toml::from_str(include_str!("../../../examples/ca.toml")).unwrap();
    example.validate_development().unwrap();
}

#[test]
fn rejects_invalid_ca_settings_before_creating_files() {
    for (field, value) in [
        ("name", serde_json::json!(" ")),
        (
            "repository_uri",
            serde_json::json!("https://example.com/rpki/"),
        ),
        (
            "certificate_uri",
            serde_json::json!("rsync://example.com/rpki/"),
        ),
        ("development_ca_validity_days", serde_json::json!(u32::MAX)),
        ("ca_renew_before_days", serde_json::json!(365)),
        ("development_resources", serde_json::json!(["192.0.2.1/24"])),
        ("development_asns", serde_json::json!([64496, 64496])),
    ] {
        let mut json = serde_json::to_value(CaConfig::default()).unwrap();
        json[field] = value;
        let config: CaConfig = serde_json::from_value(json).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("ca");
        assert!(crate::CaManager::init(&out, config).is_err(), "{field}");
        assert!(!out.exists());
    }
    let timing = IssuanceTimingConfig {
        roa_valid_weeks: u32::MAX,
        ..Default::default()
    };
    assert!(timing.validate().is_err());
}

#[test]
fn rejects_unsafe_publication_timing() {
    let timing = IssuanceTimingConfig {
        publish_next_jitter_hours: 13,
        ..IssuanceTimingConfig::default()
    };
    assert!(timing.validate().is_err());
    let timing = IssuanceTimingConfig {
        publish_hours_before_next: 24,
        ..IssuanceTimingConfig::default()
    };
    assert!(timing.validate().is_err());
}
