use crate::{CaManager, ObjectKind};
use anyhow::Result;

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
