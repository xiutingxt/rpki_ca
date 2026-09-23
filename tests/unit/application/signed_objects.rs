use super::*;
use crate::{CaConfig, ToaRequest};

fn toa() -> ObjectDefinition {
    ObjectDefinition::Toa(ToaRequest {
        asns: vec![64497, 64496, 64496],
        prefixes: vec!["192.0.2.0/24".parse().unwrap()],
        roa_overlap_justification: None,
    })
}

#[test]
fn toa_replay_is_content_idempotent_and_can_be_recreated_after_withdrawal() {
    let root = tempfile::tempdir().unwrap();
    let manager = CaManager::init(root.path(), CaConfig::default()).unwrap();

    let first = issue(&manager, toa()).unwrap();
    assert_eq!(first.action, IssueAction::Created);
    let replay = issue(&manager, toa()).unwrap();
    assert_eq!(replay.action, IssueAction::Unchanged);
    assert_eq!(replay.object_name, first.object_name);

    withdraw(&manager, ObjectKind::Toa, &first.logical_key)
        .unwrap()
        .unwrap();
    let recreated = issue(&manager, toa()).unwrap();
    assert_eq!(recreated.action, IssueAction::Created);
    assert_ne!(recreated.object_name, first.object_name);
}
