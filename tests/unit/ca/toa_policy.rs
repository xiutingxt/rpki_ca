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

#[test]
fn indexed_coverage_matches_full_scan_and_preserves_all_sources() {
    let mut index = ToaRoaIndex::default();
    for (asn, prefix, max_length, name) in [
        (64496, "192.0.2.0/24", 26, "a.roa"),
        (64496, "192.0.2.0/25", 25, "b.roa"),
        (64496, "2001:db8::/32", 48, "v6.roa"),
        (64497, "192.0.2.0/24", 24, "other.roa"),
        (0, "0.0.0.0/0", 32, "zero.roa"),
    ] {
        index.by_asn.entry(asn).or_default().push(RoaAuthorization {
            asn,
            prefix: prefix.parse().unwrap(),
            max_length,
            name: name.into(),
        });
    }
    for asns in [
        vec![64496, 64496, 64497, 64500, 0],
        vec![64500],
        vec![64496],
    ] {
        let request = request(
            asns,
            vec![
                "192.0.2.0/25",
                "192.0.2.0/25",
                "192.0.2.0/27",
                "198.51.100.0/24",
                "2001:db8::/48",
                "2001:db8::/64",
            ],
            None,
        );
        let actual = index.evaluate(&request);
        let mut expected_pairs = 0;
        let mut expected_sources = BTreeSet::new();
        for asn in request.canonical_asns() {
            for prefix in request.canonical_prefixes() {
                let mut covered = false;
                for authorization in index.by_asn.values().flatten() {
                    if authorization.covers(asn, &prefix) {
                        covered = true;
                        expected_sources.insert(authorization.name.clone());
                    }
                }
                expected_pairs += usize::from(covered);
            }
        }
        assert_eq!(
            actual.total_pairs,
            request.canonical_asns().len() * request.canonical_prefixes().len()
        );
        assert_eq!(actual.covered_pairs, expected_pairs);
        assert_eq!(actual.covering_roas, expected_sources);
    }
    let overlap = index.evaluate(&request(vec![64496], vec!["192.0.2.0/25"], None));
    assert_eq!(overlap.covered_pairs, 1);
    assert_eq!(
        overlap.covering_roas,
        BTreeSet::from(["a.roa".into(), "b.roa".into()])
    );
    let empty = ToaRoaIndex::default().evaluate(&request(vec![64496], vec!["192.0.2.0/24"], None));
    assert_eq!(empty.total_pairs, 1);
    assert_eq!(empty.covered_pairs, 0);
}
