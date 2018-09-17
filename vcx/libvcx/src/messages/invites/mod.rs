pub mod accept;
pub mod send;

extern crate serde;
extern crate rmp_serde;

use messages::{MsgType};
use utils::error;
use serde::Deserialize;
use self::rmp_serde::Deserializer;

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct KeyDlgProofPayload {
    #[serde(rename = "agentDID")]
    pub agent_did: String,
    #[serde(rename = "agentDelegatedKey")]
    pub agent_delegated_key: String,
    #[serde(rename = "signature")]
    pub signature: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct SenderDetail {
    pub name: Option<String>,
    pub agent_key_dlg_proof: KeyDlgProofPayload,
    #[serde(rename = "DID")]
    pub did: String,
    pub logo_url: Option<String>,
    #[serde(rename = "verKey")]
    pub verkey: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct MsgDetailResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    pub invite_detail: InviteDetail,
    url_to_invite_detail: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct InviteDetail {
    status_code: String,
    pub conn_req_id: String,
    pub sender_detail: SenderDetail,
    pub sender_agency_detail: SenderAgencyDetail,
    target_name: String,
    status_msg: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct SenderAgencyDetail {
    #[serde(rename = "DID")]
    pub did: String,
    #[serde(rename = "verKey")]
    pub verkey: String,
    pub endpoint: String,
}

impl InviteDetail {
    pub fn new() -> InviteDetail {
        InviteDetail {
            status_code: String::new(),
            conn_req_id: String::new(),
            sender_detail: SenderDetail {
                name: Some(String::new()),
                agent_key_dlg_proof: KeyDlgProofPayload {
                    agent_did: String::new(),
                    agent_delegated_key: String::new(),
                    signature: String::new(),
                },
                did: String::new(),
                logo_url: Some(String::new()),
                verkey: String::new(),
            },
            sender_agency_detail: SenderAgencyDetail {
                did: String::new(),
                verkey: String::new(),
                endpoint: String::new(),
            },
            target_name: String::new(),
            status_msg: String::new(),
        }
    }
}

pub fn parse_invitation_acceptance_details(payload: Vec<u8>) -> Result<SenderDetail,u32> {
    #[serde(rename_all = "camelCase")]
    #[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
    struct Details {
        sender_detail: SenderDetail,
    }

    debug!("parsing invitation acceptance details: {:?}", payload);
    let mut de = Deserializer::new(&payload[..]);
    let response: Details = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => return Err(error::INVALID_MSGPACK.code_num),
    };
    Ok(response.sender_detail.to_owned())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invitation_acceptance_details() {
        let payload = vec![129, 172, 115, 101, 110, 100, 101, 114, 68, 101, 116, 97, 105, 108, 131, 163, 68, 73, 68, 182, 67, 113, 85, 88, 113, 53, 114, 76, 105, 117, 82, 111, 100, 55, 68, 67, 52, 97, 86, 84, 97, 115, 166, 118, 101, 114, 75, 101, 121, 217, 44, 67, 70, 86, 87, 122, 118, 97, 103, 113, 65, 99, 117, 50, 115, 114, 68, 106, 117, 106, 85, 113, 74, 102, 111, 72, 65, 80, 74, 66, 111, 65, 99, 70, 78, 117, 49, 55, 113, 117, 67, 66, 57, 118, 71, 176, 97, 103, 101, 110, 116, 75, 101, 121, 68, 108, 103, 80, 114, 111, 111, 102, 131, 168, 97, 103, 101, 110, 116, 68, 73, 68, 182, 57, 54, 106, 111, 119, 113, 111, 84, 68, 68, 104, 87, 102, 81, 100, 105, 72, 49, 117, 83, 109, 77, 177, 97, 103, 101, 110, 116, 68, 101, 108, 101, 103, 97, 116, 101, 100, 75, 101, 121, 217, 44, 66, 105, 118, 78, 52, 116, 114, 53, 78, 88, 107, 69, 103, 119, 66, 56, 81, 115, 66, 51, 109, 109, 109, 122, 118, 53, 102, 119, 122, 54, 85, 121, 53, 121, 112, 122, 90, 77, 102, 115, 74, 56, 68, 122, 169, 115, 105, 103, 110, 97, 116, 117, 114, 101, 217, 88, 77, 100, 115, 99, 66, 85, 47, 99, 89, 75, 72, 49, 113, 69, 82, 66, 56, 80, 74, 65, 43, 48, 51, 112, 121, 65, 80, 65, 102, 84, 113, 73, 80, 74, 102, 52, 84, 120, 102, 83, 98, 115, 110, 81, 86, 66, 68, 84, 115, 67, 100, 119, 122, 75, 114, 52, 54, 120, 87, 116, 80, 43, 78, 65, 68, 73, 57, 88, 68, 71, 55, 50, 50, 103, 113, 86, 80, 77, 104, 117, 76, 90, 103, 89, 67, 103, 61, 61];
        println!("payload: {:?}", payload);
        let response = parse_invitation_acceptance_details(payload).unwrap();
        println!("response: {:?}", response);
    }
}
