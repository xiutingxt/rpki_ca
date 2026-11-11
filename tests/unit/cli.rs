use super::*;

#[test]
fn sispi_commands_require_asn_without_legacy_aliases() {
    for flag in ["--asn", "--as-id"] {
        let sign = Cli::try_parse_from([
            "rpki-ca",
            "sign-sispi",
            flag,
            "64496",
            "--address",
            "192.0.2.1",
            "--output",
            "example.sav",
        ]);
        let withdraw = Cli::try_parse_from(["rpki-ca", "withdraw-sispi", flag, "64496"]);
        let verify = Cli::try_parse_from([
            "rpki-ca",
            "verify-sispi",
            flag,
            "64496",
            "--object",
            "example.sav",
            "--address",
            "192.0.2.1",
        ]);
        if flag == "--asn" {
            assert!(matches!(
                sign.unwrap().command,
                Some(Command::SignSispi { asn: 64496, .. })
            ));
            assert!(matches!(
                withdraw.unwrap().command,
                Some(Command::WithdrawSispi { asn: 64496, .. })
            ));
            assert!(matches!(
                verify.unwrap().command,
                Some(Command::VerifySispi { asn: 64496, .. })
            ));
        } else {
            assert!(sign.is_err());
            assert!(withdraw.is_err());
            assert!(verify.is_err());
        }
    }
}

#[test]
fn configuration_file_conflicts_only_with_explicit_settings() {
    assert!(Cli::try_parse_from(["rpki-ca", "init", "--config", "ca.toml", "--dir", "ca"]).is_ok());
    for flag in [
        "--name",
        "--repository-uri",
        "--roa-valid-weeks",
        "--resource",
    ] {
        assert!(
            Cli::try_parse_from(["rpki-ca", "init", "--config", "ca.toml", flag, "1"]).is_err()
        );
    }
    assert!(Cli::try_parse_from(["rpki-ca", "ca-info", "--dir", "ca"]).is_ok());
    assert!(Cli::try_parse_from(["rpki-ca", "check-config", "--config", "ca.toml"]).is_ok());
}

#[test]
fn parses_direct_roa_prefixes() {
    let plain = "192.0.2.0/24".parse::<CliRoaPayload>().unwrap().0;
    assert_eq!(plain.prefix, "192.0.2.0/24".parse::<IpNet>().unwrap());
    assert_eq!(plain.max_length, None);
    assert_eq!(
        "2001:db8::/48,64"
            .parse::<CliRoaPayload>()
            .unwrap()
            .0
            .max_length,
        Some(64)
    );
}
