extern crate rust_base58;
extern crate serde_json;

use std::collections::HashMap;
use std::vec::Vec;
use utils::error;
use messages::validation;

static PROOF_REQUEST: &str = "PROOF_REQUEST";
static PROOF_DATA: &str = "proof_request_data";
static REQUESTED_ATTRS: &str = "requested_attributes";
static REQUESTED_PREDICATES: &str = "requested_predicates";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct ProofType {
//    name: String,
    #[serde(rename = "version")]
    type_version: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct ProofTopic {
    mid: u32,
    tid: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AttrInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrictions: Option<Vec<Filter>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Filter {
    pub schema_id: Option<String>,
    pub schema_issuer_did: Option<String>,
    pub schema_name: Option<String>,
    pub schema_version: Option<String>,
    pub issuer_did: Option<String>,
    pub cred_def_id: Option<String>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PredicateInfo {
    pub name: String,
    pub p_type: String,
    pub p_value: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrictions: Option<Vec<Filter>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ProofPredicates {
    predicates: Vec<PredicateInfo>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ProofRequestData{
//    nonce: String,
//    name: String,
//    #[serde(rename = "version")]
//    data_version: String,
    pub requested_attributes: HashMap<String, AttrInfo>,
//    pub requested_predicates: HashMap<String, PredicateInfo>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ProofRequestMessage{
    #[serde(rename = "@type")]
    type_header: ProofType,
//    #[serde(rename = "@topic")]
//    topic: ProofTopic,
    pub proof_request_data: ProofRequestData,
//    pub msg_ref_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ProofRequestBuilder {
    tid: Option<Result<u32, u32>>,
    mid: Option<Result<u32, u32>>,
    type_version: Option<Result<String, u32>>,
    nonce: Option<Result<String, u32>>,
    name: Option<Result<String, u32>>,
    data_version: Option<Result<String, u32>>,
    requested_attributes: Option<Result<HashMap<String, AttrInfo>, u32>>,
    requested_predicates: Option<Result<String, u32>>,
    msg_ref_id: Option<Result<String, u32>>
}

pub trait MsgUtils {
    fn mandatory_field<T>(&self, field: Option<Result<T, u32>>) -> Result<T, u32> {
        field.ok_or(error::MISSING_MSG_FIELD.code_num)?
    }
}
impl MsgUtils for ProofRequestBuilder {}
impl ProofRequestBuilder {
    pub fn new() -> ProofRequestBuilder {
        ProofRequestBuilder {
            tid: None,
            mid: None,
            type_version: None,
            nonce: None,
            name: None,
            data_version: None,
            requested_attributes: None,
            requested_predicates: None,
            msg_ref_id: None
        }
    }

    pub fn type_version(mut self, version: &str) -> ProofRequestBuilder {
        self.type_version = Some(Ok(version.to_string()));
        self
    }

    pub fn requested_attrs(mut self, attrs: &str) -> ProofRequestBuilder {
        let mut check_req_attrs: HashMap<String, AttrInfo> = HashMap::new();
        let proof_attrs:Vec<AttrInfo> = match serde_json::from_str(attrs) {
            Ok(a) => a,
            Err(e) => {
                debug!("Cannot parse attributes: {}", e);
                self.requested_attributes = Some(Err(error::INVALID_JSON.code_num));
                return self
            }
        };

        for (index, attr) in proof_attrs.iter().enumerate() {
            if check_req_attrs.contains_key(&attr.name) {
                check_req_attrs.insert(format!("{}_{}", attr.name, index), attr.clone());
            } else {
                check_req_attrs.insert(attr.name.clone(), attr.clone());
            }
        }
        self.requested_attributes = Some(Ok(check_req_attrs));
        self
    }

    pub fn build(self) -> Result<ProofRequestMessage, u32> {
        Ok(ProofRequestMessage {
            type_header: ProofType {
                type_version: self.mandatory_field(self.type_version.clone())?
            },
            proof_request_data: ProofRequestData {
                requested_attributes: self.mandatory_field(self.requested_attributes.clone())?
            }

        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_sets_attrs_correctly() {
        let req_builder = ProofRequestBuilder::new()
            .type_version("123");
        assert_eq!(req_builder.type_version.unwrap().unwrap(), "123".to_string());

    }

    #[test]
    fn test_mandatory_field() {
        let rc = ProofRequestBuilder::new()
            .build();
        assert_eq!(rc, Err(error::MISSING_MSG_FIELD.code_num));

        let rc = ProofRequestBuilder::new()
            .type_version("123")
            .requested_attrs("{}")
            .build();

        assert_eq!(rc, Err(error::INVALID_JSON.code_num));
    }
}
