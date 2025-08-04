//! Certificate Revocation List types

use crate::{
    Version,
    certificate::{Profile, Rfc5280},
    ext::ExtensionsGeneric,
    name::Name,
    serial_number::SerialNumber,
    time::Time,
};

use alloc::vec::Vec;

use der::asn1::{BitString, Int, OctetString, OctetStringRef};
use der::{DecodeValue, DerOrd, Encode, EncodeValue, FixedTag, Sequence, ValueOrd};

#[cfg(feature = "pem")]
use der::pem::PemLabel;
use spki::AlgorithmIdentifierOwned;
use crate::serial_number::IntLike;

/// `CertificateList` as defined in [RFC 5280 Section 5.1].
///
/// ```text
/// CertificateList  ::=  SEQUENCE  {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct CertificateListGeneric<OctetStringType, IntType, P: Profile = Rfc5280>
where for<'a> OctetStringType: FixedTag + Encode + DerOrd + DecodeValue<'a, Error = der::Error> + 'a,
      for<'a> IntType: DerOrd + IntLike<'a> + EncodeValue + DecodeValue<'a, Error = der::Error> + 'a{
    pub tbs_cert_list: TbsCertList<OctetStringType, IntType, P>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

pub type CertificateList<P: Profile = Rfc5280> = CertificateListGeneric<OctetString, Int, P>;

#[cfg(feature = "pem")]
impl<OctetStringType, IntType, P: Profile> PemLabel for CertificateListGeneric<OctetStringType, IntType, P>
where for<'a> OctetStringType: FixedTag + Encode + DerOrd + DecodeValue<'a, Error = der::Error> + 'a,
      for<'a> IntType: DerOrd + IntLike<'a> + EncodeValue + DecodeValue<'a, Error = der::Error> + 'a{
    const PEM_LABEL: &'static str = "X509 CRL";
}

/// Implicit intermediate structure from the ASN.1 definition of `TBSCertList`.
///
/// This type is used for the `revoked_certificates` field of `TbsCertList`.
/// See [RFC 5280 Section 5.1].
///
/// ```text
/// RevokedCert ::= SEQUENCE {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct RevokedCert<OctetStringType, IntType, P: Profile = Rfc5280>
where for<'a> OctetStringType: FixedTag + Encode + DerOrd + DecodeValue<'a, Error = der::Error> + 'a,
      for<'a> IntType: DerOrd + IntLike<'a> + EncodeValue + DecodeValue<'a, Error = der::Error> + 'a {
    pub serial_number: SerialNumber<IntType, P>,
    pub revocation_date: Time,
    pub crl_entry_extensions: Option<ExtensionsGeneric<OctetStringType>>,
}

/// `TbsCertList` as defined in [RFC 5280 Section 5.1].
///
/// ```text
/// TBSCertList  ::=  SEQUENCE  {
///      version                 Version OPTIONAL, -- if present, MUST be v2
///      signature               AlgorithmIdentifier,
///      issuer                  Name,
///      thisUpdate              Time,
///      nextUpdate              Time OPTIONAL,
///      revokedCertificates     SEQUENCE OF SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL -- if present, version MUST be v2
///      }  OPTIONAL,
///      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL -- if present, version MUST be v2
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct TbsCertList<OctetStringType, IntType, P: Profile = Rfc5280>
where for<'a> OctetStringType: FixedTag + Encode + DerOrd + DecodeValue<'a, Error = der::Error> + 'a,
      for<'a> IntType: DerOrd + IntLike<'a> + EncodeValue + DecodeValue<'a, Error = der::Error> + 'a{
    pub version: Version,
    pub signature: AlgorithmIdentifierOwned,
    pub issuer: Name,
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub revoked_certificates: Option<Vec<RevokedCert<OctetStringType, IntType, P>>>,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl_extensions: Option<ExtensionsGeneric<OctetStringType>>,
}
