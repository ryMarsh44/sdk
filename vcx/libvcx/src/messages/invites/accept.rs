extern crate rust_base58;
extern crate serde_json;
extern crate serde;
extern crate rmp_serde;
extern crate base64;

use settings;
use utils::libindy::{crypto, wallet};
use utils::httpclient;
use utils::error;
use messages::*;
use messages::invites::{KeyDlgProofPayload, SenderDetail, SenderAgencyDetail};
use utils::constants::*;
use serde::Deserialize;
use self::rmp_serde::Deserializer;
use self::rmp_serde::encode;
use std::str;


#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct MsgCreateResponse {
    #[serde(rename = "@type")]
    pub msg_type: MsgType,
    pub uid: String,
}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct AcceptMsgDetailPayload {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "keyDlgProof")]
    key_proof: KeyDlgProofPayload,
    sender_detail: Option<SenderDetail>,
    sender_agency_detail: Option<SenderAgencyDetail>,
    answer_status_code: Option<String>
}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct AcceptInvitePayload{
    create_payload: CreateMessagePayload,
    msg_detail_payload: AcceptMsgDetailPayload,
}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInvite {
    #[serde(rename = "to")]
    to_did: String,
    to_vk: String,
    #[serde(skip_serializing, default)]
    payload: AcceptInvitePayload,
    agent_did: String,
    agent_vk: String,
}

pub struct AcceptInviteBuilder {
    to_did: Option<Result<String, u32>>,
    to_vk: Option<Result<String, u32>>,
    agent_did: Option<Result<String, u32>>,
    agent_vk: Option<Result<String, u32>>,
    key_delegate: Option<String>,
    sender_detail: Option<SenderDetail>,
    sender_agency_detail: Option<SenderAgencyDetail>,
    answer_status_code: Option<String>,
    reply_to: Option<String>,
}

impl MsgUtils for AcceptInviteBuilder {}
impl GeneralMessageBuilder for AcceptInviteBuilder {
    type MsgBuilder = AcceptInviteBuilder;
    type Msg = AcceptInvite;

    fn new() -> AcceptInviteBuilder {
        AcceptInviteBuilder {
            to_did: None,
            to_vk: None,
            agent_did: None,
            agent_vk: None,
            key_delegate: None,
            sender_detail: None,
            sender_agency_detail: None,
            answer_status_code: None,
            reply_to: None,
        }
    }

    fn to(mut self, did: &str) -> Self::MsgBuilder {
        self.to_did = Some(validation::validate_did(did));
        self
    }

    fn to_vk(mut self, vk: &str) -> Self::MsgBuilder {
        self.to_vk = Some(validation::validate_verkey(vk));
        self
    }

    fn agent_did(mut self, did: &str) -> Self::MsgBuilder {
        self.agent_did = Some(validation::validate_did(did));
        self
    }

    fn agent_vk(mut self, vk: &str) -> Self::MsgBuilder {
        self.agent_vk = Some(validation::validate_verkey(vk));
        self.key_delegate = Some(vk.to_string());
        self
    }

    fn build(self) -> Result<Self::Msg, u32> {
        let build_err = error::MISSING_MSG_FIELD.code_num;

        let to_did = self.to_did.clone().ok_or(build_err)??;
        let to_vk = self.to_vk.clone().ok_or(build_err)??;
        let agent_did = self.agent_did.clone().ok_or(build_err)??;
        let agent_vk = self.agent_vk.clone().ok_or(build_err)??;
        let agent_delegated_key = self.key_delegate.unwrap_or_default();
        let signature = AcceptInviteBuilder::generate_signature(&to_vk, &agent_did, &agent_delegated_key)?;

        let create_payload = CreateMessagePayload {
            msg_type: MsgType { name: "CREATE_MSG".to_string(), ver: "1.0".to_string() },
            mtype: "connReqAnswer".to_string(),
            reply_to_msg_id: Some(self.reply_to.clone().ok_or(build_err)?),
            send_msg: true
        };

        let msg_detail_payload = AcceptMsgDetailPayload {
            msg_type: MsgType { name: "MSG_DETAIL".to_string(), ver: "1.0".to_string(), } ,
            key_proof: KeyDlgProofPayload {
                agent_did: agent_did.clone(),
                agent_delegated_key,
                signature
            },
            sender_detail: self.sender_detail,
            sender_agency_detail: self.sender_agency_detail,
            answer_status_code: self.answer_status_code
        };

        Ok(AcceptInvite {
            to_did,
            to_vk,
            agent_did,
            agent_vk,
            payload: AcceptInvitePayload {
                create_payload,
                msg_detail_payload
            }
        })
    }
}

impl AcceptInviteBuilder{

    pub fn key_delegate(mut self, key: &str) -> AcceptInviteBuilder {
        self.key_delegate = Some(key.to_string());
        self
    }

    pub fn sender_details(mut self, details: &SenderDetail) -> AcceptInviteBuilder {
        self.sender_detail = Some(details.clone());
        self
    }

    pub fn sender_agency_details(mut self, details: &SenderAgencyDetail) -> AcceptInviteBuilder  {
        self.sender_agency_detail = Some(details.clone());
        self
    }

    pub fn answer_status_code(mut self, code: &str) -> AcceptInviteBuilder  {
        self.answer_status_code = Some(code.to_owned());
        self
    }

    pub fn reply_to(mut self, id: &str) -> AcceptInviteBuilder {
        self.reply_to = Some(id.to_owned());
        self
    }

    pub fn generate_signature(to_vk: &str, agent_did: &str, agent_delegated_key: &str) -> Result<String, u32> {
        let signature = format!("{}{}", agent_did, agent_delegated_key);
        let signature = crypto::sign(wallet::get_wallet_handle(), to_vk, signature.as_bytes())?;
        let signature = base64::encode(&signature);
        Ok(signature.to_string())
    }
}

impl GeneralMessage for AcceptInvite{
    type SendSecureResult = String;

    fn msgpack(&mut self) -> Result<Vec<u8>,u32> {
        debug!("connection invitation details: {:?}", &self.payload.msg_detail_payload);
        let create = encode::to_vec_named(&self.payload.create_payload).or(Err(error::UNKNOWN_ERROR.code_num))?;
        let details = encode::to_vec_named(&self.payload.msg_detail_payload).or(Err(error::UNKNOWN_ERROR.code_num))?;

        let mut bundle = Bundled::create(create);
        bundle.bundled.push(details);

        let msg = bundle.encode()?;

        bundle_for_agent(msg, &self.to_vk, &self.agent_did, &self.agent_vk)
    }

    fn send_secure(&mut self) -> Result<Self::SendSecureResult, u32> {
        let data = self.msgpack()?;

        if settings::test_agency_mode_enabled() { httpclient::set_next_u8_response(ACCEPT_INVITE_RESPONSE.to_vec()); }

        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => {
                parse_send_accept_response(response)
            },
        }
    }
}

const ACCEPT_BUNDLE_LEN: usize = 2;
fn parse_send_accept_response(response: Vec<u8>) -> Result<String, u32> {
    let data = unbundle_from_agency(response)?;

    if data.len() != ACCEPT_BUNDLE_LEN {
        error!("expected {} messages (got {})",ACCEPT_BUNDLE_LEN, data.len());
        return Err(error::INVALID_MSGPACK.code_num);
    }
    debug!("create msg response: {:?}", data[0]);
    let mut de = Deserializer::new(&data[0][..]);
    let response: MsgCreateResponse = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("Could not parse messagepack: {}", x);
            return Err(error::INVALID_MSGPACK.code_num)
        },
    };

    Ok(response.uid.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_invite_builder(){
        init!("true");

        let to_did = "8XFh8yBzrpJQmNyZzgoTqB";
        let to_vk = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let agent_did = "8XFh8yBzrpJQmNyZzgoTzz";
        let agent_vk = "BBBBa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let sender_details = SenderDetail {
            name: None,
            agent_key_dlg_proof: KeyDlgProofPayload {
                agent_did: agent_did.to_string(),
                agent_delegated_key: agent_vk.to_string(),
                signature: "".to_string(),
            },
            did: to_did.to_string(),
            logo_url: None,
            verkey: to_vk.to_string(),
        };
        let accept: AcceptInvite = AcceptInviteBuilder::new()
            .to(to_did)
            .to_vk(to_vk)
            .agent_did(agent_did)
            .agent_vk(agent_vk)
            .sender_details(&sender_details)
            .answer_status_code("MS-104")
            .reply_to("123")
            .build().unwrap();
    }

}