//! Protocol constants that are not supplied by the `rpki` crate.

/// Experimental allocation used while draft-qin-savnet-toa-02 still has a
/// TBD IANA value. Replace this constant after IANA assigns the final arc.
pub const TOA_CONTENT_TYPE_OID: &str = "1.2.840.113549.1.9.16.1.999";

/// DER content octets for [`TOA_CONTENT_TYPE_OID`].
pub const TOA_CONTENT_TYPE_OID_BYTES: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 135, 103];

/// Experimental allocation used while draft-chen-sidrops-sispi-06 still has
/// an IANA TBD for id-ct-rpkiSiSPI. It must be replaced before production use.
pub const SISPI_CONTENT_TYPE_OID: &str = "1.2.840.113549.1.9.16.1.998";

/// DER content octets for [`SISPI_CONTENT_TYPE_OID`].
pub const SISPI_CONTENT_TYPE_OID_BYTES: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 135, 102];
