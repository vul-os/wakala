//! The structured operator policy carried in a [`broker_economics::Descriptor::policy`]'s opaque
//! `Cbor` payload (CONTRACT §2.1: "opaque operator policy — region, capabilities, contact").
//!
//! `broker_economics` deliberately leaves this payload's shape to the caller (it only carries and
//! signs over the bytes). This module gives the admin API's PUT-descriptor request a concrete,
//! typed shape, encoded through the real canonical deterministic CBOR codec
//! ([`kotva_core::cbor`]) — the same one the descriptor signature is computed over — rather than
//! inventing an ad hoc JSON-in-CBOR blob.

use kotva_core::cbor::{as_array, as_text, CborError, Cv, Fields};
use serde::{Deserialize, Serialize};

use broker_economics::Cbor;

/// Wire layout (this module's own `Cv`, before wrapping in `Cbor`):
/// ```text
/// {
///   1: region,        tstr?  — OPTIONAL, e.g. "eu-west"
///   2: capabilities,  arr?   — OPTIONAL, array of tstr capability tags
///   3: contact,       tstr?  — OPTIONAL, operator contact (email/URL/...)
///   4: notes,         tstr?  — OPTIONAL, free-text operator note
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPolicy {
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub contact: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl OperatorPolicy {
    fn to_cv(&self) -> Cv {
        let mut m = Vec::new();
        if let Some(r) = &self.region {
            m.push((1u64, Cv::Text(r.clone())));
        }
        if !self.capabilities.is_empty() {
            m.push((
                2,
                Cv::Array(self.capabilities.iter().cloned().map(Cv::Text).collect()),
            ));
        }
        if let Some(c) = &self.contact {
            m.push((3, Cv::Text(c.clone())));
        }
        if let Some(n) = &self.notes {
            m.push((4, Cv::Text(n.clone())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let region = f.take(1).map(as_text).transpose()?;
        let capabilities = match f.take(2) {
            Some(cv) => as_array(cv)?
                .into_iter()
                .map(as_text)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let contact = f.take(3).map(as_text).transpose()?;
        let notes = f.take(4).map(as_text).transpose()?;
        f.deny_unknown()?;
        Ok(OperatorPolicy {
            region,
            capabilities,
            contact,
            notes,
        })
    }

    /// Encode as the [`Cbor`] payload a [`broker_economics::Descriptor::policy`] carries.
    pub fn to_cbor(&self) -> Cbor {
        Cbor::from_cv(&self.to_cv())
    }

    /// Decode a policy out of a descriptor's `policy` field. An empty payload (no policy
    /// declared) decodes to the default (all fields absent).
    pub fn from_cbor(c: &Cbor) -> Result<Self, CborError> {
        if c.0.is_empty() {
            return Ok(Self::default());
        }
        Self::from_cv(c.decode()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_cbor() {
        let p = OperatorPolicy {
            region: Some("eu-west".into()),
            capabilities: vec!["relay".into(), "media-relay".into()],
            contact: Some("ops@example.org".into()),
            notes: Some("reference deployment".into()),
        };
        let decoded = OperatorPolicy::from_cbor(&p.to_cbor()).expect("decodes");
        assert_eq!(decoded, p);
    }

    #[test]
    fn empty_policy_round_trips() {
        let p = OperatorPolicy::default();
        let decoded = OperatorPolicy::from_cbor(&p.to_cbor()).expect("decodes");
        assert_eq!(decoded, p);
        assert_eq!(OperatorPolicy::from_cbor(&Cbor::empty()).unwrap(), p);
    }
}
