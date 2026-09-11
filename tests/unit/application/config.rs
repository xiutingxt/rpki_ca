use super::*;

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
