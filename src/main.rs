mod api;
mod application;
mod ca;
mod domain;
mod infrastructure;
mod objects;
mod validation;

pub use application::{
    config::{CaConfig, IssuanceTimingConfig},
    manager::CaManager,
};
pub use ca::CertificateAuthority;
pub use domain::{
    model::{
        CaCertificateRenewal, CaCertificateStatus, CaImportRequest, ObjectDefinition, ObjectKind,
    },
    resources::CertifiedResources,
};
pub use objects::{AspaRequest, RoaPayload, RoaRequest};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Parser)]
#[command(name = "rpki-ca", version, about = "Minimal file-backed RPKI CA")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
        #[arg(long)]
        repository_uri: String,
        /// Public rsync URI of the imported RC itself (not its parent).
        #[arg(long)]
        certificate_uri: String,
        /// First unused certificate serial for this CA.
        #[arg(long)]
        serial_start: u64,
        /// First unused CRL Number for this CA.
        #[arg(long)]
        crl_number_start: u64,
        /// First unused Manifest Number for this publication point.
        #[arg(long)]
        manifest_number_start: u64,
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
    /// Sign an ROA request into an RFC 9582 .roa object.
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
    /// Withdraw a published ROA and revoke its EE certificate.
    WithdrawRoa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        object: String,
    },
    /// Withdraw the ASPA for a Customer ASN and revoke its EE certificate.
    WithdrawAspa {
        #[arg(long, default_value = "data")]
        dir: PathBuf,
        #[arg(long)]
        customer_asn: u32,
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
struct CliRoaPayload(RoaPayload);

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

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            dir,
            repository_uri,
            name,
            development_ca_validity_days,
            ca_renew_before_days,
            roa_valid_weeks,
            aspa_valid_weeks,
            publish_next_hours,
            publish_next_jitter_hours,
            publish_hours_before_next,
            resources,
            asn_resources,
        } => {
            let config = CaConfig {
                name,
                repository_uri,
                // CaManager replaces this with the RFC 6481 key-derived URI
                // after generating the development CA key.
                certificate_uri: String::new(),
                development_ca_validity_days,
                ca_renew_before_days,
                timing: IssuanceTimingConfig {
                    roa_valid_weeks,
                    aspa_valid_weeks,
                    publish_next_hours,
                    publish_next_jitter_hours,
                    publish_hours_before_next,
                },
                development_resources: if resources.is_empty() {
                    CaConfig::default().development_resources
                } else {
                    resources
                },
                development_asns: asn_resources,
            };
            CaManager::init(&dir, config)?;
            println!("CA initialized in {}", dir.display());
        }
        Command::Import {
            dir,
            certificate,
            private_key,
            repository_uri,
            certificate_uri,
            serial_start,
            crl_number_start,
            manifest_number_start,
            chain,
            crls,
            manifests,
        } => {
            let config = CaConfig {
                repository_uri,
                certificate_uri,
                ..CaConfig::default()
            };
            let certificate_bytes = fs::read(&certificate)
                .with_context(|| format!("cannot read {}", certificate.display()))?;
            let private_key_pem = fs::read_to_string(&private_key)
                .with_context(|| format!("cannot read {}", private_key.display()))?;
            let chain_bytes = chain
                .iter()
                .map(|path| {
                    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let crl_bytes = crls
                .iter()
                .map(|path| {
                    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let manifest_bytes = manifests
                .iter()
                .map(|path| {
                    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            CaManager::import(
                &dir,
                config,
                CaImportRequest {
                    certificate: certificate_bytes,
                    private_key_pem,
                    serial_start,
                    crl_number_start,
                    manifest_number_start,
                    chain: chain_bytes,
                    crls: crl_bytes,
                    manifests: manifest_bytes,
                },
            )?;
            println!("resource CA imported into {}", dir.display());
        }
        Command::SignRoa {
            dir,
            request,
            asn,
            prefix,
            output,
        } => {
            ensure_external_export(&dir, &output)?;
            let request = match (request, asn) {
                (Some(path), None) => {
                    let json = fs::read(&path)
                        .with_context(|| format!("cannot read {}", path.display()))?;
                    serde_json::from_slice(&json).context("invalid ROA request JSON")?
                }
                (None, Some(asn)) => RoaRequest {
                    asn,
                    prefixes: prefix.into_iter().map(|item| item.0).collect(),
                },
                _ => anyhow::bail!("provide either --request or both --asn and --prefix"),
            };
            let object_name = output
                .file_name()
                .and_then(|value| value.to_str())
                .context("output must have a UTF-8 filename")?;
            let manager = CaManager::open(&dir)?;
            let bytes = manager.sign_roa(&request, object_name)?;
            let published_name = manager
                .published_name(&format!("roa:{object_name}"))?
                .context("signed ROA is missing from CA state")?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, bytes)?;
            println!(
                "ROA published as repository/{published_name}; exported to {}",
                output.display()
            );
        }
        Command::SignAspa {
            dir,
            customer_asn,
            provider_asns,
            output,
        } => {
            ensure_external_export(&dir, &output)?;
            let request = AspaRequest {
                customer_asn,
                provider_asns,
            };
            let object_name = output
                .file_name()
                .and_then(|value| value.to_str())
                .context("output must have a UTF-8 filename")?;
            let manager = CaManager::open(&dir)?;
            let bytes = manager.sign_aspa(&request, object_name)?;
            let published_name = manager
                .published_name(&format!("aspa:AS{customer_asn}"))?
                .context("signed ASPA is missing from CA state")?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, bytes)?;
            println!(
                "ASPA published as repository/{published_name}; exported to {}",
                output.display()
            );
        }
        Command::WithdrawRoa { dir, object } => {
            let changed = CaManager::open(dir)?.withdraw_roa(&object)?;
            println!(
                "ROA withdrawal: {}",
                if changed {
                    "published"
                } else {
                    "already absent"
                }
            );
        }
        Command::WithdrawAspa { dir, customer_asn } => {
            let changed = CaManager::open(dir)?.withdraw_aspa(customer_asn)?;
            println!(
                "ASPA withdrawal: {}",
                if changed {
                    "published"
                } else {
                    "already absent"
                }
            );
        }
        Command::Refresh { dir } => {
            CaManager::open(&dir)?.refresh()?;
            println!("CRL and manifest refreshed in {}", dir.display());
        }
        Command::CertificateStatus { dir } => {
            let status = CaManager::open(dir)?.certificate_status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::RenewCertificate {
            dir,
            certificate,
            chain,
            crls,
            manifests,
        } => {
            let renewal = CaCertificateRenewal {
                certificate: read_file(&certificate)?,
                chain: read_files(&chain)?,
                crls: read_files(&crls)?,
                manifests: read_files(&manifests)?,
            };
            CaManager::open(&dir)?.renew_certificate(renewal)?;
            println!("CA certificate renewed in {}", dir.display());
        }
        Command::VerifyRoa {
            dir,
            object,
            asn,
            prefixes,
        } => {
            let expected = prefixes
                .into_iter()
                .map(|item| {
                    let prefix = item.0.prefix;
                    let max = item.0.max_length.unwrap_or(prefix.prefix_len());
                    format!("{}/{}-{max}", prefix.addr(), prefix.prefix_len())
                })
                .collect::<Vec<_>>();
            for line in validation::verify_roa_publication(&dir, &object, asn, &expected)? {
                println!("[PASS] {line}");
            }
            println!("RESULT: PASS - publication set is internally consistent");
        }
        Command::VerifyAspa {
            dir,
            object,
            customer_asn,
            provider_asns,
        } => {
            for line in
                validation::verify_aspa_publication(&dir, &object, customer_asn, &provider_asns)?
            {
                println!("[PASS] {line}");
            }
            println!("RESULT: PASS - ASPA publication set is internally consistent");
        }
        Command::Serve {
            dir,
            bind,
            token_env,
        } => {
            let token = std::env::var(&token_env)
                .with_context(|| format!("environment variable {token_env} is required"))?;
            if token.trim().is_empty() {
                anyhow::bail!("environment variable {token_env} must not be empty");
            }
            let cors_origin = std::env::var("CORS_ORIGIN").ok();
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(api::serve(dir, &bind, token, cors_origin))?;
        }
    }
    Ok(())
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn read_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths.iter().map(|path| read_file(path)).collect()
}

fn ensure_external_export(ca_root: &Path, output: &Path) -> Result<()> {
    let repository = fs::canonicalize(ca_root.join("repository"))
        .context("CA publication repository does not exist")?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let export_parent = fs::canonicalize(parent)
        .with_context(|| format!("cannot resolve export directory {}", parent.display()))?;
    if export_parent.starts_with(&repository) {
        anyhow::bail!(
            "--output is an external export path and must not be inside {}; the CA manages RFC 6481 repository filenames",
            repository.display()
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
