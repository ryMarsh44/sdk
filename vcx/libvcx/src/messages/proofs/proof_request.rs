extern crate rust_base58;
extern crate serde_json;

use std::collections::HashMap;
use std::vec::Vec;
use std::fmt;
use utils::error;
use messages::MsgUtils;
use messages::validation;

static PROOF_REQUEST: &str = "PROOF_REQUEST";
static PROOF_DATA: &str = "proof_request_data";
static REQUESTED_ATTRS: &str = "requested_attributes";
static REQUESTED_PREDICATES: &str = "requested_predicates";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct ProofType {
    name: String,
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
    nonce: String,
    name: String,
    #[serde(rename = "version")]
    data_version: String,
    pub requested_attributes: HashMap<String, AttrInfo>,
    pub requested_predicates: HashMap<String, PredicateInfo>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ProofRequestMessage{
    #[serde(rename = "@type")]
    type_header: ProofType,
    #[serde(rename = "@topic")]
    topic: ProofTopic,
    pub proof_request_data: ProofRequestData,
    pub msg_ref_id: Option<String>,
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
    requested_predicates: Option<Result<HashMap<String, PredicateInfo>, u32>>,
    msg_ref_id: Option<Result<String, u32>>
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
        self.type_version = self.wrap_ok(version.to_string());
        self
    }

    pub fn tid(mut self, tid: u32) -> ProofRequestBuilder {
        self.tid = self.wrap_ok(tid);
        self
    }

    pub fn mid(mut self, mid: u32) -> ProofRequestBuilder {
        self.mid = self.wrap_ok(mid);
        self
    }

    pub fn nonce(mut self, nonce: &str) -> ProofRequestBuilder {
        self.nonce = Some(validation::validate_nonce(nonce));
        self
    }

    pub fn proof_name(mut self, name: &str) -> ProofRequestBuilder {
        self.name = self.wrap_ok(name.to_string());
        self
    }

    pub fn proof_data_version(mut self, version: &str) -> ProofRequestBuilder {
        self.data_version = self.wrap_ok(version.to_string());
        self
    }

    pub fn requested_attrs(mut self, attrs: &str) -> ProofRequestBuilder {
        let mut check_req_attrs: HashMap<String, AttrInfo> = HashMap::new();
        let proof_attrs:Vec<AttrInfo> = match serde_json::from_str(attrs) {
            Ok(a) => a,
            Err(e) => {
                debug!("Cannot parse attributes: {}", e);
                self.requested_attributes = self.wrap_err(error::INVALID_JSON.code_num);
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
        self.requested_attributes = self.wrap_ok(check_req_attrs);
        self
    }

    pub fn requested_predicates(mut self, predicates: &str) -> ProofRequestBuilder {
        let mut check_predicates: HashMap<String, PredicateInfo> = HashMap::new();
        let attr_values: Vec<PredicateInfo> = match serde_json::from_str(predicates) {
            Ok(a) => a,
            Err(e) => {
                debug!("Cannot parse predicates: {}", e);
                self.requested_predicates = self.wrap_err(error::INVALID_JSON.code_num);
                return self
            },
        };

        for (index, attr) in attr_values.iter().enumerate() {
            if check_predicates.contains_key(&attr.name) {
                check_predicates.insert(format!("{}_{}", attr.name, index), attr.clone());
            } else {
                check_predicates.insert(attr.name.clone(), attr.clone());
            }
        }

        self.requested_predicates = self.wrap_ok(check_predicates);
        self
    }

    pub fn build(self) -> Result<ProofRequestMessage, u32> {
        Ok(ProofRequestMessage {
            type_header: ProofType {
                name: String::from(PROOF_REQUEST),
                type_version: self.mandatory_field(self.type_version.clone())?
            },
            topic: ProofTopic {
                tid: self.mandatory_field(self.tid.clone())?,
                mid: self.mandatory_field(self.mid.clone())?,
            },
            proof_request_data: ProofRequestData {
                nonce: self.mandatory_field(self.nonce.clone())?,
                name: self.mandatory_field(self.name.clone())?,
                data_version: self.mandatory_field(self.data_version.clone())?,
                requested_attributes: self.mandatory_field(self.requested_attributes.clone())?,
                requested_predicates: self.mandatory_field(self.requested_predicates.clone())?
            },
            msg_ref_id: None
        })
    }
}

impl fmt::Display for ProofRequestMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match serde_json::to_string(&self) {
            Ok(x) => {
                write!(f, "{}", x)
            },
            Err(e) => {
                error!("{}: {:?}", error::INVALID_PROOF_REQ.message, e);
                write!(f, "null")
            }
        }
    }
}

impl ProofRequestMessage {
    pub fn get_proof_request_data(&self) -> String { json!(self)[PROOF_DATA].to_string() }

    pub fn serialize_message(&self) -> String { self.to_string() }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use utils::constants::{REQUESTED_ATTRS, REQUESTED_PREDICATES};

    pub fn populated_proof_req_builder() -> ProofRequestBuilder {
        //proof data
        let data_name = "Test";
        let nonce = "123432421212";
        let data_version = "3.75";
        let attrs = "";
        let version = "1.3";
        let tid = 89;
        let mid = 98;

        ProofRequestBuilder::new()
            .type_version(version)
            .tid(tid)
            .mid(mid)
            .nonce(nonce)
            .proof_name(data_name)
            .proof_data_version(data_version)
            .requested_attrs(REQUESTED_ATTRS)
            .requested_predicates(REQUESTED_PREDICATES)
    }

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

        assert!(rc.is_err());
    }

    #[test]
    fn test_proof_request_msg() {
        let serialized_msg =  populated_proof_req_builder()
            .build()
            .unwrap()
            .serialize_message();

        println!("{}", serialized_msg);
        assert!(serialized_msg.contains(r#""@type":{"name":"PROOF_REQUEST","version":"1.3"}"#));
        assert!(serialized_msg.contains(r#"@topic":{"mid":98,"tid":89}"#));
        assert!(serialized_msg.contains(r#"proof_request_data":{"nonce":"123432421212","name":"Test","version":"3.75","requested_attributes""#));

        assert!(serialized_msg.contains(r#""age":{"name":"age","restrictions":[{"schema_id":"6XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11","schema_issuer_did":"6XFh8yBzrpJQmNyZzgoTqB","schema_name":"Faber Student Info","schema_version":"1.0","issuer_did":"8XFh8yBzrpJQmNyZzgoTqB","cred_def_id":"8XFh8yBzrpJQmNyZzgoTqB:3:CL:1766"},{"schema_id":"5XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11","schema_issuer_did":"5XFh8yBzrpJQmNyZzgoTqB","schema_name":"BYU Student Info","schema_version":"1.0","issuer_did":"66Fh8yBzrpJQmNyZzgoTqB","cred_def_id":"66Fh8yBzrpJQmNyZzgoTqB:3:CL:1766"}]}"#));
    }

    #[test]
    fn test_requested_attrs_constructed_correctly() {
        let mut check_req_attrs: HashMap<String, AttrInfo> = HashMap::new();
        let attr_info1: AttrInfo = serde_json::from_str(r#"{ "name":"age", "restrictions": [ { "schema_id": "6XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"Faber Student Info", "schema_version":"1.0", "schema_issuer_did":"6XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"8XFh8yBzrpJQmNyZzgoTqB", "cred_def_id": "8XFh8yBzrpJQmNyZzgoTqB:3:CL:1766" }, { "schema_id": "5XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"BYU Student Info", "schema_version":"1.0", "schema_issuer_did":"5XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"66Fh8yBzrpJQmNyZzgoTqB", "cred_def_id": "66Fh8yBzrpJQmNyZzgoTqB:3:CL:1766" } ] }"#).unwrap();
        let attr_info2: AttrInfo = serde_json::from_str(r#"{ "name":"name", "restrictions": [ { "schema_id": "6XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"Faber Student Info", "schema_version":"1.0", "schema_issuer_did":"6XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"8XFh8yBzrpJQmNyZzgoTqB", "cred_def_id": "8XFh8yBzrpJQmNyZzgoTqB:3:CL:1766" }, { "schema_id": "5XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"BYU Student Info", "schema_version":"1.0", "schema_issuer_did":"5XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"66Fh8yBzrpJQmNyZzgoTqB", "cred_def_id": "66Fh8yBzrpJQmNyZzgoTqB:3:CL:1766" } ] }"#).unwrap();

        check_req_attrs.insert("age".to_string(), attr_info1);
        check_req_attrs.insert("name".to_string(), attr_info2);

        assert_eq!(populated_proof_req_builder().requested_attributes, Some(Ok(check_req_attrs)));
    }

    #[test]
    fn test_requested_predicates_constructed_correctly() {
        let mut check_predicates: HashMap<String, PredicateInfo> = HashMap::new();
        let attr_info1: PredicateInfo = serde_json::from_str(r#"{ "name":"age","p_type":"GE","p_value":22, "restrictions":[ { "schema_id": "6XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"Faber Student Info", "schema_version":"1.0", "schema_issuer_did":"6XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"8XFh8yBzrpJQmNyZzgoTqB", "cred_def_id": "8XFh8yBzrpJQmNyZzgoTqB:3:CL:1766" }, { "schema_id": "5XFh8yBzrpJQmNyZzgoTqB:2:schema_name:0.0.11", "schema_name":"BYU Student Info", "schema_version":"1.0", "schema_issuer_did":"5XFh8yBzrpJQmNyZzgoTqB", "issuer_did":"66Fh8yBzrpJQmNyZzgoTqB", "cred_def_id": "66Fh8yBzrpJQmNyZzgoTqB:3:CL:1766" } ] }"#).unwrap();
        check_predicates.insert("age".to_string(), attr_info1);

        assert_eq!(populated_proof_req_builder().requested_predicates, Some(Ok(check_predicates)));
    }

    #[test]
    fn test_indy_proof_req_parses_correctly() {
        let proof_req: ProofRequestData = serde_json::from_str(::utils::constants::INDY_PROOF_REQ_JSON).unwrap();
    }
}
