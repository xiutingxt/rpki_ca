use crate::{CaManager, ObjectDefinition, ObjectKind};
use anyhow::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IssueAction {
    Created,
    Updated,
    Unchanged,
}

#[derive(Clone, Debug)]
pub(crate) struct IssueResult {
    pub logical_key: String,
    pub object_name: String,
    pub action: IssueAction,
    pub advisories: Vec<String>,
}

pub(crate) fn issue(manager: &CaManager, definition: ObjectDefinition) -> Result<IssueResult> {
    let definition = definition.canonicalized();
    let logical_key = definition.logical_key();
    let requested_name = requested_name(&definition, &logical_key);
    let current = manager.signed_object(&logical_key)?;
    let (object_name, advisories, action) = match current {
        Some(current) if current.definition.as_ref() == Some(&definition) => {
            (current.object_name, Vec::new(), IssueAction::Unchanged)
        }
        current => {
            let output = match manager.sign_object(definition, &requested_name) {
                Ok(output) => output,
                Err(error) => return Err(error),
            };
            let action = if current.is_some() {
                IssueAction::Updated
            } else {
                IssueAction::Created
            };
            (output.name, output.advisories, action)
        }
    };
    Ok(IssueResult {
        logical_key,
        object_name,
        action,
        advisories,
    })
}

pub(crate) fn get(
    manager: &CaManager,
    kind: ObjectKind,
    logical_key: &str,
) -> Result<Option<crate::SignedObjectView>> {
    Ok(manager
        .signed_object(logical_key)?
        .filter(|object| object.kind == kind))
}

pub(crate) fn withdraw(
    manager: &CaManager,
    kind: ObjectKind,
    logical_key: &str,
) -> Result<Option<crate::ObjectWithdrawal>> {
    manager.withdraw_signed_object(logical_key, kind)
}

fn requested_name(definition: &ObjectDefinition, logical_key: &str) -> String {
    match definition {
        ObjectDefinition::Roa(_) => "derived.roa".into(),
        ObjectDefinition::Aspa(request) => format!("aspa-AS{}.asa", request.customer_asn),
        ObjectDefinition::Sispi(request) => format!("sispi-AS{}.sav", request.as_id),
        ObjectDefinition::Toa(_) => format!("toa-{}.toa", &logical_key[4..28]),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/application/signed_objects.rs"]
mod tests;
