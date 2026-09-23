//! DER codec for the TrafficOriginAttestation eContent.

use bcder::encode::{PrimitiveContent, Values};
use bcder::{Mode, Tag, decode, encode};
use rpki::repository::{
    cert::{Cert, ResourceCert},
    error::VerificationError,
    resources::{AddressFamily, Asn, IpResources, IpResourcesBuilder, Prefix},
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ToaContent {
    asns: Vec<Asn>,
    v4_prefixes: Vec<Prefix>,
    v6_prefixes: Vec<Prefix>,
}

impl ToaContent {
    pub(super) fn new(asns: Vec<Asn>, v4_prefixes: Vec<Prefix>, v6_prefixes: Vec<Prefix>) -> Self {
        Self {
            asns,
            v4_prefixes,
            v6_prefixes,
        }
    }

    pub fn asns(&self) -> &[Asn] {
        &self.asns
    }

    pub fn v4_prefixes(&self) -> &[Prefix] {
        &self.v4_prefixes
    }

    pub fn v6_prefixes(&self) -> &[Prefix] {
        &self.v6_prefixes
    }

    pub(super) fn v4_resources(&self) -> IpResources {
        resources_for(&self.v4_prefixes)
    }

    pub(super) fn v6_resources(&self) -> IpResources {
        resources_for(&self.v6_prefixes)
    }

    pub(super) fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, decode::DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            if cons
                .take_opt_constructed_if(Tag::CTX_0, |inner| inner.skip_u8_if(0))?
                .is_some()
            {
                return Err(
                    cons.content_err("TOA version 0 is a DEFAULT value and must be omitted in DER")
                );
            }
            let mut asns: Vec<Asn> = Vec::new();
            cons.take_sequence(|values| {
                while let Some(asn) = Asn::take_opt_from(values)? {
                    if asns.last().is_some_and(|last| *last >= asn) {
                        return Err(values.content_err("TOA ASIDs are not strictly increasing"));
                    }
                    asns.push(asn);
                    if asns.len() > 10_000 {
                        return Err(values.content_err("TOA contains more than 10000 ASIDs"));
                    }
                }
                if asns.is_empty() {
                    return Err(values.content_err("TOA asSet is empty"));
                }
                Ok(())
            })?;
            let mut v4_prefixes = Vec::new();
            let mut v6_prefixes = Vec::new();
            let mut last_afi = 0u8;
            cons.take_sequence(|families| {
                while let Some(()) = families.take_opt_sequence(|family| {
                    let family_kind = AddressFamily::take_from(family)?;
                    let afi = match family_kind {
                        AddressFamily::Ipv4 => 1,
                        AddressFamily::Ipv6 => 2,
                    };
                    if afi <= last_afi {
                        return Err(family.content_err("duplicate or non-canonical TOA AFI"));
                    }
                    last_afi = afi;
                    let prefixes = match family_kind {
                        AddressFamily::Ipv4 => &mut v4_prefixes,
                        AddressFamily::Ipv6 => &mut v6_prefixes,
                    };
                    let start = prefixes.len();
                    family.take_sequence(|addresses| {
                        while let Some(raw) = addresses
                            .take_opt_value_if(Tag::BIT_STRING, |content| {
                                Prefix::parse_content_with_family(content, family_kind)
                            })?
                        {
                            if afi == 1 && raw.addr_len() > 32 {
                                return Err(addresses.content_err("invalid IPv4 TOA prefix length"));
                            }
                            if prefixes
                                .last()
                                .is_some_and(|last| sort_key(*last) >= sort_key(raw))
                            {
                                return Err(
                                    addresses.content_err("duplicate or non-canonical TOA prefix")
                                );
                            }
                            prefixes.push(raw);
                        }
                        if prefixes.len() == start {
                            return Err(addresses.content_err("TOA address family is empty"));
                        }
                        Ok(())
                    })
                })? {}
                if last_afi == 0 {
                    return Err(families.content_err("TOA ipAddrBlocks is empty"));
                }
                Ok(())
            })?;
            Ok(Self {
                asns,
                v4_prefixes,
                v6_prefixes,
            })
        })
    }

    pub(super) fn verify_ee_profile(&self, cert: &Cert) -> Result<(), VerificationError> {
        if cert.v4_resources().is_inherited() || cert.v6_resources().is_inherited() {
            return Err(VerificationError::new(
                "TOA EE certificate contains inherited IP resources",
            ));
        }
        if cert.as_resources().is_present() {
            return Err(VerificationError::new(
                "TOA EE certificate contains forbidden AS resources",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_resources(&self, cert: &ResourceCert) -> Result<(), VerificationError> {
        for (family, prefix) in self
            .v4_prefixes
            .iter()
            .map(|prefix| (AddressFamily::Ipv4, *prefix))
            .chain(
                self.v6_prefixes
                    .iter()
                    .map(|prefix| (AddressFamily::Ipv6, *prefix)),
            )
        {
            let covered = match family {
                AddressFamily::Ipv4 => cert.v4_resources().contains_block(prefix),
                AddressFamily::Ipv6 => cert.v6_resources().contains_block(prefix),
            };
            if !covered {
                let prefix = match family {
                    AddressFamily::Ipv4 => format!("{}/{}", prefix.to_v4(), prefix.addr_len()),
                    AddressFamily::Ipv6 => format!("{}/{}", prefix.to_v6(), prefix.addr_len()),
                };
                return Err(VerificationError::new(format!(
                    "TOA prefix {prefix} is not covered by its EE certificate"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn encode_ref(&self) -> impl Values + '_ {
        encode_content(&self.asns, &self.v4_prefixes, &self.v6_prefixes)
    }
}

fn encode_content<'a>(
    asns: &'a [Asn],
    v4_prefixes: &'a [Prefix],
    v6_prefixes: &'a [Prefix],
) -> impl Values + 'a {
    encode::sequence((
        encode::sequence(encode::iter(asns.iter().map(|asn| asn.encode()))),
        encode::sequence((
            encode_family(AddressFamily::Ipv4, v4_prefixes),
            encode_family(AddressFamily::Ipv6, v6_prefixes),
        )),
    ))
}

fn encode_family<'a>(family: AddressFamily, prefixes: &'a [Prefix]) -> Option<impl Values + 'a> {
    let values = prefixes
        .iter()
        .map(|prefix| prefix.encode().to_captured(Mode::Der))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    Some(encode::sequence((
        family.encode(),
        encode::sequence(values).to_captured(Mode::Der),
    )))
}

fn resources_for(prefixes: &[Prefix]) -> IpResources {
    let mut resources = IpResourcesBuilder::new();
    resources.blocks(|blocks| {
        for prefix in prefixes {
            blocks.push(*prefix);
        }
    });
    resources.finalize()
}

fn sort_key(prefix: Prefix) -> (u128, u8) {
    (prefix.addr().to_bits(), prefix.addr_len())
}

#[cfg(test)]
#[path = "../../../../tests/unit/ca/toa_profile.rs"]
mod tests;
