use clap::{CommandFactory, Parser, Subcommand};
use ipnet::IpNet;
use rpki_ca::RoaPayload;
use std::{net::IpAddr, path::PathBuf, str::FromStr};

#[derive(Parser)]
#[command(name = "rpki-ca", version, about = "Minimal file-backed RPKI CA")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Initialize a development trust-anchor CA.
    Init {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long, default_value = "rsync://localhost/rpki/")]
        repository_uri: String,
        #[arg(long, default_value = "development-ca")]
        name: String,
        #[arg(long, default_value_t = 365)]
        development_ca_validity_days: u32,
        #[arg(long, default_value_t = 30)]
        ca_renew_before_days: u32,
        #[arg(long, default_value_t = 52)]
        roa_valid_weeks: u32,
        #[arg(long, default_value_t = 52)]
        aspa_valid_weeks: u32,
        #[arg(long, default_value_t = 52)]
        sispi_valid_weeks: u32,
        #[arg(long, default_value_t = 52)]
        toa_valid_weeks: u32,
        #[arg(long, default_value_t = 90)]
        toa_review_days: u32,
        #[arg(long, default_value_t = 24)]
        publish_next_hours: u32,
        #[arg(long, default_value_t = 4)]
        publish_next_jitter_hours: u32,
        #[arg(long, default_value_t = 8)]
        publish_hours_before_next: u32,
        /// Explicit resources for the development TA; may be repeated.
        #[arg(long = "resource")]
        resources: Vec<IpNet>,
        /// Explicit ASN resources for the development TA; may be repeated.
        #[arg(long = "asn-resource")]
        asn_resources: Vec<u32>,
    },
    /// Import an existing DER resource CA certificate and matching RSA key.
    Import {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        /// TAL that pins the trust anchor public key for this certificate path.
        #[arg(long)]
        tal: PathBuf,
        #[arg(long)]
        repository_uri: String,
        /// Public rsync URI of the imported RC itself (not its parent).
        #[arg(long)]
        certificate_uri: String,
        /// First unused certificate serial for this CA.
        #[arg(long)]
        serial_start: u64,
        /// First number used for both CRL Number and Manifest Number.
        #[arg(long)]
        publication_number_start: u64,
        /// DER certificates ordered from the trust anchor to the direct parent.
        #[arg(long = "chain-certificate")]
        chain: Vec<PathBuf>,
        /// Current issuer CRLs in the same order as the issuing CAs.
        #[arg(long = "chain-crl")]
        crls: Vec<PathBuf>,
        /// Current issuer manifests in the same order as --chain-certificate.
        #[arg(long = "chain-manifest")]
        manifests: Vec<PathBuf>,
    },
    /// Add ROA authorizations and export the derived RFC 9582 object.
    SignRoa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        /// JSON request file. Conflicts with --asn and --prefix.
        #[arg(long, conflicts_with_all = ["asn", "prefix"])]
        request: Option<PathBuf>,
        /// Origin ASN for a request supplied directly on the CLI.
        #[arg(long, requires = "prefix")]
        asn: Option<u32>,
        /// PREFIX or PREFIX,MAX_LENGTH; may be repeated.
        #[arg(long, requires = "asn")]
        prefix: Vec<CliRoaPayload>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Atomically add/remove ROA authorizations from a JSON RoaDelta file.
    UpdateRoas {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        delta: PathBuf,
    },
    /// List desired ROA authorizations and their derived repository objects.
    ListRoas {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
    },
    /// Sign an ASPA object using the current IETF ASPA profile draft.
    SignAspa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        customer_asn: u32,
        #[arg(long = "provider-asn", required = true)]
        provider_asns: Vec<u32>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign an experimental draft-qin-savnet-toa-02 TOA object.
    SignToa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long = "asn", required = true)]
        asns: Vec<u32>,
        #[arg(long = "prefix", required = true)]
        prefixes: Vec<IpNet>,
        /// Required when all TOA (ASN, prefix) pairs are already covered by ROAs.
        #[arg(long)]
        roa_overlap_justification: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// List periodic review state for all currently issued TOAs.
    ListToaReviews {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
    },
    /// Record a periodic operational review of a published TOA.
    ReviewToa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
        /// Required if the TOA is now entirely covered by existing ROAs.
        #[arg(long)]
        roa_overlap_justification: Option<String>,
    },
    /// Sign an experimental draft-chen-sidrops-sispi-06 SiSPI object.
    SignSispi {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        as_id: u32,
        #[arg(long = "address", required = true)]
        addresses: Vec<IpAddr>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Withdraw the ASPA for a Customer ASN and revoke its EE certificate.
    WithdrawAspa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        customer_asn: u32,
    },
    /// Withdraw a published TOA and revoke its EE certificate.
    WithdrawToa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
    },
    /// Withdraw the SiSPI for an AS and revoke its EE certificate.
    WithdrawSispi {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        as_id: u32,
    },
    /// Reissue the CRL and manifest; schedule this before manifest nextUpdate.
    Refresh {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
    },
    /// Show the CA certificate lifetime and renewal state as JSON.
    CertificateStatus {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
    },
    /// Install a renewed certificate for the existing CA key.
    RenewCertificate {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        /// TAL that pins the trust anchor public key for this certificate path.
        #[arg(long)]
        tal: PathBuf,
        #[arg(long = "chain-certificate")]
        chain: Vec<PathBuf>,
        #[arg(long = "chain-crl")]
        crls: Vec<PathBuf>,
        #[arg(long = "chain-manifest")]
        manifests: Vec<PathBuf>,
    },
    /// Refresh the TAL, parent certificates, CRLs, and manifests used for
    /// full-path validation of an imported resource CA.
    UpdateValidationContext {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        tal: PathBuf,
        #[arg(long = "chain-certificate")]
        chain: Vec<PathBuf>,
        #[arg(long = "chain-crl")]
        crls: Vec<PathBuf>,
        #[arg(long = "chain-manifest")]
        manifests: Vec<PathBuf>,
    },
    /// Verify a published ROA and its CA certificate, CRL, and manifest.
    VerifyRoa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long)]
        asn: u32,
        /// Expected PREFIX,MAX_LENGTH; may be repeated.
        #[arg(long = "prefix", required = true)]
        prefixes: Vec<CliRoaPayload>,
    },
    /// Verify a published ASPA and its CA certificate, CRL, and manifest.
    VerifyAspa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long)]
        customer_asn: u32,
        #[arg(long = "provider-asn", required = true)]
        provider_asns: Vec<u32>,
    },
    /// Verify a published experimental TOA and its publication set.
    VerifyToa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long = "asn", required = true)]
        asns: Vec<u32>,
        #[arg(long = "prefix", required = true)]
        prefixes: Vec<IpNet>,
    },
    /// Verify a published experimental SiSPI and its publication set.
    VerifySispi {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long)]
        as_id: u32,
        #[arg(long = "address", required = true)]
        addresses: Vec<IpAddr>,
    },
    /// Run the HTTP API server.
    Serve {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long, default_value = "0.0.0.0:3000")]
        bind: String,
        /// Environment variable containing the bearer token.
        #[arg(long, default_value = "API_TOKEN")]
        token_env: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct CliRoaPayload(pub(super) RoaPayload);

impl FromStr for CliRoaPayload {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (prefix, max_length) = match value.rsplit_once(',') {
            Some((prefix, max)) => {
                let max = max
                    .parse::<u8>()
                    .map_err(|_| format!("invalid max length in '{value}'"))?;
                (prefix, Some(max))
            }
            None => (value, None),
        };
        let prefix = prefix
            .parse::<IpNet>()
            .map_err(|err| format!("invalid prefix '{prefix}': {err}"))?;
        Ok(Self(RoaPayload { prefix, max_length }))
    }
}

pub(super) fn parse_command() -> Option<Command> {
    Cli::parse().command
}

pub(super) fn print_help() -> Result<(), clap::Error> {
    Cli::command().print_help()?;
    println!();
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/cli.rs"]
mod tests;
