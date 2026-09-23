use super::publication_set::PublicationSet;
use crate::{
    ca::parent::ParentValidationContext,
    ca::signed_objects::{sispi::object::Sispi, toa::object::Toa},
    infrastructure::repository::PublicationRepository,
};
use bytes::Bytes;
use chrono::Utc;
use rpki::repository::{aspa::Aspa, roa::Roa};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Valid,
    Invalid,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: ValidationStatus,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationReport {
    pub name: String,
    pub scope: &'static str,
    pub overall: ValidationStatus,
    pub validated_at: String,
    pub checks: Vec<ValidationCheck>,
    pub limitation: &'static str,
}

impl ValidationReport {
    fn new(name: &str, validation_context: &ParentValidationContext) -> Self {
        let limitation = if validation_context.is_imported() {
            "父级证书、CRL 和 Manifest 使用最近一次导入或更新的本地快照；本接口不主动从 RRDP/rsync 获取上级发布数据"
        } else {
            "开发模式使用本地自签信任锚；该信任锚不属于全球 RPKI 信任体系"
        };
        Self {
            name: name.to_owned(),
            scope: "configured_trust_anchor_to_current_publication",
            overall: ValidationStatus::Valid,
            validated_at: Utc::now().to_rfc3339(),
            checks: Vec::new(),
            limitation,
        }
    }

    fn valid(&mut self, id: &'static str, label: &'static str, message: impl Into<String>) {
        self.checks.push(ValidationCheck {
            id,
            label,
            status: ValidationStatus::Valid,
            message: message.into(),
        });
    }

    fn invalid(&mut self, id: &'static str, label: &'static str, message: impl Into<String>) {
        self.overall = ValidationStatus::Invalid;
        self.checks.push(ValidationCheck {
            id,
            label,
            status: ValidationStatus::Invalid,
            message: message.into(),
        });
    }
}

pub(crate) fn validate_repository_object(
    repository: &dyn PublicationRepository,
    validation_context: &ParentValidationContext,
    name: &str,
) -> ValidationReport {
    let mut report = ValidationReport::new(name, validation_context);
    let publication = match PublicationSet::load(repository, validation_context) {
        Ok(publication) => publication,
        Err(error) => {
            if name.ends_with(".toa") {
                eprintln!("TOA validation failed for {name}: {error:#}");
            }
            report.invalid(
                "publication_set",
                "CA、CRL 与 Manifest",
                format!("当前发布集无效：{error:#}"),
            );
            return report;
        }
    };
    let path_message = if validation_context.is_imported() {
        "从配置的 TAL 经全部父级 CA 到当前 CA 的证书、CRL、Manifest、签名、有效期和资源约束检查通过"
    } else {
        "本地开发信任锚的自签名、Profile、有效期和资源约束检查通过"
    };
    report.valid("ca_certificate", "CA 完整认证路径", path_message);
    report.valid("crl", "当前 CRL", "CRL 签名、签发者、AKI 和有效期检查通过");
    report.valid(
        "manifest",
        "当前 Manifest",
        "Manifest CMS、EE 证书、有效期、文件清单及全部文件哈希检查通过",
    );

    let extension = name.rsplit_once('.').map(|(_, value)| value);
    if matches!(extension, Some("cer" | "crl" | "mft")) {
        report.valid(
            "repository_object",
            "发布对象",
            "该基础设施对象属于已验证的当前发布集",
        );
        return report;
    }

    let validation = match extension {
        Some("roa") => validate_roa(&publication, name),
        Some("asa") => validate_aspa(&publication, name),
        Some("toa") => validate_toa(&publication, name),
        Some("sav") => validate_sispi(&publication, name),
        _ => Err("不支持验证该文件类型".to_owned()),
    };
    match validation {
        Ok(()) => {
            report.valid(
                "publication_binding",
                "Manifest、哈希与吊销状态",
                "对象由当前 Manifest 收录且哈希匹配，EE 证书未被当前 CRL 吊销",
            );
            report.valid(
                "signed_object",
                "CMS、EE 证书与对象 Profile",
                "rpki Signed Object 验证、EE 证书验证及对象特定资源覆盖检查通过",
            );
        }
        Err(error) => {
            if extension == Some("toa") {
                eprintln!("TOA validation failed for {name}: {error}");
            }
            report.invalid("signed_object", "签名对象与发布绑定", error);
        }
    }
    report
}

fn validate_roa(publication: &PublicationSet, name: &str) -> Result<(), String> {
    let bytes = publication
        .object_bytes(name)
        .map_err(|error| error.to_string())?;
    let roa = Roa::decode(bytes.as_slice(), true).map_err(|error| error.to_string())?;
    publication
        .validate_object(name, roa.cert(), "roa")
        .map_err(|error| error.to_string())?;
    roa.process(&publication.ca, true, |_| Ok(()))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_aspa(publication: &PublicationSet, name: &str) -> Result<(), String> {
    let bytes = publication
        .object_bytes(name)
        .map_err(|error| error.to_string())?;
    let aspa = Aspa::decode(bytes.as_slice(), true).map_err(|error| error.to_string())?;
    publication
        .validate_object(name, aspa.cert(), "asa")
        .map_err(|error| error.to_string())?;
    aspa.process(&publication.ca, true, |_| Ok(()))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_toa(publication: &PublicationSet, name: &str) -> Result<(), String> {
    let bytes = publication
        .object_bytes(name)
        .map_err(|error| error.to_string())?;
    let toa = Toa::decode(Bytes::from(bytes)).map_err(|error| error.to_string())?;
    publication
        .validate_object(name, toa.cert(), "toa")
        .map_err(|error| error.to_string())?;
    toa.process(&publication.ca, |_| Ok(()))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_sispi(publication: &PublicationSet, name: &str) -> Result<(), String> {
    let bytes = publication
        .object_bytes(name)
        .map_err(|error| error.to_string())?;
    let sispi = Sispi::decode(Bytes::from(bytes)).map_err(|error| error.to_string())?;
    publication
        .validate_object(name, sispi.cert(), "sav")
        .map_err(|error| error.to_string())?;
    sispi
        .process(&publication.ca, |_| Ok(()))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/validation/report.rs"]
mod tests;
