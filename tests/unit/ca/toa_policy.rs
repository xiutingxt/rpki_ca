use super::*;

fn request(asns: Vec<u32>, prefixes: Vec<&str>, reason: Option<&str>) -> ToaRequest {
    ToaRequest {
        asns,
        prefixes: prefixes
            .into_iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect(),
        roa_overlap_justification: reason.map(str::to_owned),
    }
}

#[test]
fn applies_roa_prefix_and_max_length_coverage() {
    let authorization = RoaAuthorization {
        asn: 64496,
        prefix: "192.0.2.0/24".parse().unwrap(),
        max_length: 26,
        name: "example.roa".into(),
    };
    assert!(authorization.covers(64496, &"192.0.2.0/25".parse().unwrap()));
    assert!(!authorization.covers(64496, &"192.0.2.0/27".parse().unwrap()));
    assert!(!authorization.covers(64497, &"192.0.2.0/25".parse().unwrap()));
    assert!(!authorization.covers(64496, &"198.51.100.0/25".parse().unwrap()));
}

#[test]
fn fully_covered_toa_requires_an_operational_reason() {
    let assessment = ToaRoaAssessment {
        total_pairs: 1,
        covered_pairs: 1,
        covering_roas: BTreeSet::from(["example.roa".into()]),
    };
    let error = assessment
        .enforce(&request(vec![64496], vec!["192.0.2.0/24"], None))
        .unwrap_err();
    assert!(error.is::<ToaRoaOverlapJustificationRequired>());
    let advisories = assessment
        .enforce(&request(
            vec![64496],
            vec!["192.0.2.0/24"],
            Some("traffic and route origins are managed separately"),
        ))
        .unwrap();
    assert_eq!(advisories.len(), 1);
}

#[test]
fn partial_overlap_keeps_one_consolidated_toa() {
    let assessment = ToaRoaAssessment {
        total_pairs: 4,
        covered_pairs: 1,
        covering_roas: BTreeSet::from(["example.roa".into()]),
    };
    let advisories = assessment
        .enforce(&request(
            vec![64496, 64497],
            vec!["192.0.2.0/24", "2001:db8::/48"],
            None,
        ))
        .unwrap();
    assert!(advisories[0].contains("单个合并 TOA"));
}
