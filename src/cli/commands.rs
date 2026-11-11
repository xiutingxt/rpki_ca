use super::{
    args::{Command, PublisherCommand, parse_command, print_help},
    io::{ensure_external_export, read_file, read_files},
};
use crate::{
    AspaRequest, CaCertificateRenewal, CaConfig, CaImportRequest, CaManager,
    CaValidationContextUpdate, IssuanceTimingConfig, ObjectDefinition, RoaDelta, RoaRequest,
    SispiRequest, ToaRequest, api, verify_aspa_publication, verify_roa_publication,
    verify_sispi_publication, verify_toa_publication,
};
use anyhow::{Context, Result};
use std::fs;

pub(crate) fn run() -> Result<()> {
    let Some(command) = parse_command() else {
        print_help()?;
        return Ok(());
    };

    match command {
        Command::Publisher { command } => match command {
            PublisherCommand::Init {
                publisher_dir,
                handle,
            } => {
                crate::publisher::init(&publisher_dir, &handle)?;
                println!(
                    "{}",
                    serde_json::json!({"status": "initialized", "request": publisher_dir.join("publisher-request.xml")})
                );
            }
            PublisherCommand::Configure {
                publisher_dir,
                response,
                ca_config_output,
                allow_http,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&crate::publisher::configure(
                        &publisher_dir,
                        &response,
                        ca_config_output.as_deref(),
                        allow_http
                    )?)?
                );
            }
            PublisherCommand::Sync {
                publisher_dir,
                dir,
                dry_run,
                allow_http,
                tls_ca,
                timeout_seconds,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&crate::publisher::sync(
                        &publisher_dir,
                        &dir,
                        dry_run,
                        allow_http,
                        tls_ca.as_deref(),
                        timeout_seconds
                    )?)?
                );
            }
        },
        Command::CaInfo { dir } => {
            println!("{}", serde_json::to_string_pretty(&crate::ca_info(&dir)?)?);
        }
        Command::CheckConfig { config } => {
            let config = CaConfig::from_file(&config)?;
            config.validate_development()?;
            println!(
                "{}",
                serde_json::json!({"status": "valid", "effective_config": config})
            );
        }
        Command::ExportExperiment { dir, output } => {
            let (valid, report) = crate::experiment::export(&dir, &output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            anyhow::ensure!(
                valid,
                "snapshot exported but validation failed; see JSON report"
            );
        }
        Command::Experiment {
            request,
            output,
            valid_days,
        } => {
            let mut request: crate::experiment::ExperimentRequest =
                serde_json::from_slice(&read_file(&request)?)?;
            if let Some(days) = valid_days {
                request.valid_days = days;
            }
            let report = crate::experiment::create(&request, &output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::VerifyExperiment { dir, tal } => {
            let (valid, report) = crate::experiment::verification_report(&dir, tal.as_deref());
            println!("{}", serde_json::to_string_pretty(&report)?);
            anyhow::ensure!(valid, "experiment validation failed; see JSON report");
        }
        Command::Init {
            config: config_file,
            dir,
            repository_uri,
            name,
            development_ca_validity_days,
            ca_renew_before_days,
            roa_valid_weeks,
            aspa_valid_weeks,
            sispi_valid_weeks,
            toa_valid_weeks,
            toa_review_days,
            publish_next_hours,
            publish_next_jitter_hours,
            publish_hours_before_next,
            resources,
            asn_resources,
        } => {
            let config = if let Some(path) = config_file {
                CaConfig::from_file(&path)?
            } else {
                CaConfig {
                    name,
                    repository_uri,
                    // CaManager replaces this with the RFC 6481 key-derived URI
                    // after generating the development CA key.
                    certificate_uri: String::new(),
                    rrdp_notification_uri: None,
                    development_ca_validity_days,
                    ca_renew_before_days,
                    timing: IssuanceTimingConfig {
                        roa_valid_weeks,
                        aspa_valid_weeks,
                        sispi_valid_weeks,
                        toa_valid_weeks,
                        toa_review_days,
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
                }
            };
            CaManager::init(&dir, config)?;
            println!("CA initialized in {}", dir.display());
        }
        Command::Import {
            dir,
            certificate,
            private_key,
            tal,
            repository_uri,
            certificate_uri,
            serial_start,
            publication_number_start,
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
                    publication_number_start,
                    chain: chain_bytes,
                    crls: crl_bytes,
                    manifests: manifest_bytes,
                    tal: read_file(&tal)?,
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
                .published_name(&format!("roa:AS{}", request.asn))?
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
        Command::UpdateRoas { dir, delta } => {
            let bytes =
                fs::read(&delta).with_context(|| format!("cannot read {}", delta.display()))?;
            let delta: RoaDelta =
                serde_json::from_slice(&bytes).context("invalid ROA delta JSON")?;
            let response = CaManager::open(dir)?.update_roas(delta)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::ListRoas { dir } => {
            let configurations = CaManager::open(dir)?.roa_configurations()?;
            println!("{}", serde_json::to_string_pretty(&configurations)?);
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
        Command::SignToa {
            dir,
            asns,
            prefixes,
            roa_overlap_justification,
            output,
        } => {
            ensure_external_export(&dir, &output)?;
            let request = ToaRequest {
                asns,
                prefixes,
                roa_overlap_justification,
            };
            let logical_name = output
                .file_name()
                .and_then(|value| value.to_str())
                .context("output must have a UTF-8 filename")?;
            let manager = CaManager::open(&dir)?;
            let definition = ObjectDefinition::Toa(request).canonicalized();
            let logical_key = definition.logical_key();
            let signed = manager.issue_object(definition, logical_name)?;
            let published_name = manager
                .published_name(&logical_key)?
                .context("signed TOA is missing from CA state")?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, signed.bytes)?;
            println!(
                "TOA published as repository/{published_name}; exported to {}",
                output.display()
            );
            for advisory in signed.advisories {
                println!("ADVISORY: {advisory}");
            }
        }
        Command::SignSispi {
            dir,
            asn,
            addresses,
            output,
        } => {
            ensure_external_export(&dir, &output)?;
            let request = SispiRequest { asn, addresses };
            let logical_name = output
                .file_name()
                .and_then(|value| value.to_str())
                .context("output must have a UTF-8 filename")?;
            let manager = CaManager::open(&dir)?;
            let bytes = manager.sign_sispi(&request, logical_name)?;
            let published_name = manager
                .published_name(&format!("sispi:AS{asn}"))?
                .context("signed SiSPI is missing from CA state")?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, bytes)?;
            println!(
                "SiSPI published as repository/{published_name}; exported to {}",
                output.display()
            );
        }
        Command::ListToaReviews { dir } => {
            let statuses = CaManager::open(dir)?.toa_review_statuses()?;
            println!("{}", serde_json::to_string_pretty(&statuses)?);
        }
        Command::ReviewToa {
            dir,
            object,
            roa_overlap_justification,
        } => {
            let status = CaManager::open(dir)?.review_toa(&object, roa_overlap_justification)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
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
        Command::WithdrawToa { dir, object } => {
            let changed = CaManager::open(dir)?.withdraw_toa(&object)?;
            println!(
                "TOA withdrawal: {}",
                if changed {
                    "published"
                } else {
                    "already absent"
                }
            );
        }
        Command::WithdrawSispi { dir, asn } => {
            let changed = CaManager::open(dir)?.withdraw_sispi(asn)?;
            println!(
                "SiSPI withdrawal: {}",
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
            tal,
            chain,
            crls,
            manifests,
        } => {
            let renewal = CaCertificateRenewal {
                certificate: read_file(&certificate)?,
                chain: read_files(&chain)?,
                crls: read_files(&crls)?,
                manifests: read_files(&manifests)?,
                tal: read_file(&tal)?,
            };
            CaManager::open(&dir)?.renew_certificate(renewal)?;
            println!("CA certificate renewed in {}", dir.display());
        }
        Command::UpdateValidationContext {
            dir,
            tal,
            chain,
            crls,
            manifests,
        } => {
            CaManager::open(&dir)?.update_validation_context(CaValidationContextUpdate {
                chain: read_files(&chain)?,
                crls: read_files(&crls)?,
                manifests: read_files(&manifests)?,
                tal: read_file(&tal)?,
            })?;
            println!("parent validation snapshot updated in {}", dir.display());
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
            for line in verify_roa_publication(&dir, &object, asn, &expected)? {
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
            for line in verify_aspa_publication(&dir, &object, customer_asn, &provider_asns)? {
                println!("[PASS] {line}");
            }
            println!("RESULT: PASS - ASPA publication set is internally consistent");
        }
        Command::VerifyToa {
            dir,
            object,
            asns,
            prefixes,
        } => {
            for line in verify_toa_publication(&dir, &object, &asns, &prefixes)? {
                println!("[PASS] {line}");
            }
            println!("RESULT: PASS - TOA publication set is internally consistent");
        }
        Command::VerifySispi {
            dir,
            object,
            asn,
            addresses,
        } => {
            for line in verify_sispi_publication(&dir, &object, asn, &addresses)? {
                println!("[PASS] {line}");
            }
            println!("RESULT: PASS - SiSPI publication set is internally consistent");
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
