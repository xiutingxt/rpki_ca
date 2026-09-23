//! DER codec for the SAVNETAttestation eContent.

use bcder::encode::{PrimitiveContent, Values};
use bcder::{Mode, Tag, decode, encode};
use rpki::repository::{
    cert::{Cert, ResourceCert},
    error::VerificationError,
    resources::{AddressFamily, AsBlock, AsResources, AsResourcesBuilder, Asn, Prefix},
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SispiContent {
    as_id: Asn,
    v4_addresses: Vec<Prefix>,
    v6_addresses: Vec<Prefix>,
}

impl SispiContent {
    pub(super) fn new(as_id: Asn, v4_addresses: Vec<Prefix>, v6_addresses: Vec<Prefix>) -> Self {
        Self {
            as_id,
            v4_addresses,
            v6_addresses,
        }
    }

    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    pub fn v4_addresses(&self) -> &[Prefix] {
        &self.v4_addresses
    }

    pub fn v6_addresses(&self) -> &[Prefix] {
        &self.v6_addresses
    }

    pub(super) fn as_resources(&self) -> AsResources {
        let mut resources = AsResourcesBuilder::new();
        resources.blocks(|blocks| blocks.push(AsBlock::Id(self.as_id)));
        resources.finalize()
    }

    pub(super) fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, decode::DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            if cons
                .take_opt_constructed_if(Tag::CTX_0, |inner| inner.skip_u8_if(0))?
                .is_some()
            {
                return Err(cons
                    .content_err("SiSPI version 0 is a DEFAULT value and must be omitted in DER"));
            }
            let as_id = Asn::take_from(cons)?;
            let mut v4_addresses = Vec::new();
            let mut v6_addresses = Vec::new();
            cons.take_sequence(|families| {
                while let Some(()) = families.take_opt_sequence(|family| {
                    let address_family = AddressFamily::take_from(family)?;
                    let addresses = match address_family {
                        AddressFamily::Ipv4 => &mut v4_addresses,
                        AddressFamily::Ipv6 => &mut v6_addresses,
                    };
                    let start = addresses.len();
                    family.take_sequence(|values| {
                        while let Some(prefix) = values
                            .take_opt_value_if(Tag::BIT_STRING, |content| {
                                Prefix::parse_content_with_family(content, address_family)
                            })?
                        {
                            if address_family == AddressFamily::Ipv4 && prefix.addr_len() > 32 {
                                return Err(values.content_err("invalid SiSPI IPv4 address"));
                            }
                            addresses.push(prefix);
                        }
                        if addresses.len() == start {
                            return Err(values.content_err("SiSPI IP address family is empty"));
                        }
                        Ok(())
                    })
                })? {}
                if v4_addresses.is_empty() && v6_addresses.is_empty() {
                    return Err(families.content_err("SiSPI addresses is empty"));
                }
                Ok(())
            })?;
            Ok(Self {
                as_id,
                v4_addresses,
                v6_addresses,
            })
        })
    }

    pub(super) fn verify_ee_profile(&self, cert: &Cert) -> Result<(), VerificationError> {
        if !cert.as_resources().is_present() {
            return Err(VerificationError::new(
                "SiSPI EE certificate has no AS Identifier Delegation Extension",
            ));
        }
        if cert.as_resources().is_inherited() {
            return Err(VerificationError::new(
                "SiSPI EE certificate contains inherited AS resources",
            ));
        }
        if cert.has_ip_resources() {
            return Err(VerificationError::new(
                "SiSPI EE certificate contains a forbidden IP Address Delegation Extension",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_resources(&self, cert: &ResourceCert) -> Result<(), VerificationError> {
        if !cert.as_resources().contains_asn(self.as_id) {
            return Err(VerificationError::new(format!(
                "SiSPI AS{} is not covered by its EE certificate",
                self.as_id.into_u32()
            )));
        }
        Ok(())
    }

    pub(super) fn encode_ref(&self) -> impl Values + '_ {
        encode_content(self.as_id, &self.v4_addresses, &self.v6_addresses)
    }
}

fn encode_content<'a>(
    as_id: Asn,
    v4_addresses: &'a [Prefix],
    v6_addresses: &'a [Prefix],
) -> impl Values + 'a {
    encode::sequence((
        as_id.encode(),
        encode::sequence((
            encode_family(AddressFamily::Ipv4, v4_addresses),
            encode_family(AddressFamily::Ipv6, v6_addresses),
        )),
    ))
}

fn encode_family<'a>(family: AddressFamily, addresses: &'a [Prefix]) -> Option<impl Values + 'a> {
    let values = addresses
        .iter()
        .map(|address| address.encode().to_captured(Mode::Der))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    Some(encode::sequence((
        family.encode(),
        encode::sequence(values).to_captured(Mode::Der),
    )))
}

#[cfg(test)]
#[path = "../../../../tests/unit/ca/sispi_profile.rs"]
mod tests;
