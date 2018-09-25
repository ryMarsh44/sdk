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
use messages::invites::{KeyDlgProofPayload, MsgDetailResponse};
use utils::constants::*;
use serde::Deserialize;
use self::rmp_serde::Deserializer;
use self::rmp_serde::encode;
use std::str;


#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct SendMsgDetailPayload {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "keyDlgProof")]
    key_proof: KeyDlgProofPayload,
    #[serde(rename = "phoneNo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct SendInvitePayload{
    create_payload: CreateMessagePayload,
    msg_detail_payload: SendMsgDetailPayload,
}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct SendInvite {
    #[serde(rename = "to")]
    to_did: String,
    to_vk: String,
    agent_did: String,
    agent_vk: String,
    #[serde(skip_serializing, default)]
    payload: SendInvitePayload,
}

pub struct SendInviteBuilder {
    base_msg: BaseMsg,
    key_delegate: Option<String>,
    phone: Option<String>,
}

impl MsgUtils for SendInviteBuilder {}
impl GeneralMessageBuilder for SendInviteBuilder {
    type MsgBuilder = SendInviteBuilder;
    type Msg = SendInvite;

    fn new() -> Self::MsgBuilder {
        SendInviteBuilder {
            base_msg: BaseMsg::new(),
            key_delegate: None,
            phone: None,
        }
    }

    fn to(mut self, did: &str) -> Self::MsgBuilder {
        &self.base_msg.to(did);
        self
    }

    fn to_vk(mut self, vk: &str) -> Self::MsgBuilder {
        self.base_msg.to_vk(vk);
        self
    }

    fn agent_did(mut self, did: &str) -> Self::MsgBuilder {
        self.base_msg.agent_did(did);
        self
    }

    fn agent_vk(mut self, vk: &str) -> Self::MsgBuilder {
        self.base_msg.agent_vk(vk);
        self.key_delegate = Some(vk.to_string());
        self
    }

    fn build(self) -> Result<Self::Msg, u32> {
        let build_err = error::MISSING_MSG_FIELD.code_num;

        let to_did = self.base_msg.to_did.clone().ok_or(build_err)??;
        let to_vk = self.base_msg.to_vk.clone().ok_or(build_err)??;
        let agent_did = self.base_msg.agent_did.clone().ok_or(build_err)??;
        let agent_vk = self.base_msg.agent_vk.clone().ok_or(build_err)??;
        let agent_delegated_key = self.key_delegate.unwrap_or_default();
        let signature = SendInviteBuilder::generate_signature(&to_vk, &agent_did, &agent_delegated_key)?;

        let create_payload = CreateMessagePayload {
            msg_type: MsgType { name: "CREATE_MSG".to_string(), ver: "1.0".to_string() },
            mtype: "connReq".to_string(),
            reply_to_msg_id: None,
            send_msg: true
        };

        let msg_detail_payload = SendMsgDetailPayload {
            msg_type: MsgType { name: "MSG_DETAIL".to_string(), ver: "1.0".to_string()},
            key_proof: KeyDlgProofPayload {
                agent_did: agent_did.clone(),
                agent_delegated_key,
                signature
            },
            phone: self.phone
        };

        Ok(SendInvite {
            to_did,
            to_vk,
            agent_did,
            agent_vk,
            payload: SendInvitePayload {
                create_payload,
                msg_detail_payload
            }
        })
    }
}

impl SendInviteBuilder{
    pub fn key_delegate(mut self, key: &str) -> SendInviteBuilder {
        self.key_delegate = Some(key.to_string());
        self
    }

    pub fn phone_number(mut self, phone_number: &Option<String>)-> SendInviteBuilder {
        self.phone = phone_number.clone();
        self
    }

    pub fn generate_signature(to_vk: &str, agent_did: &str, agent_delegated_key: &str) -> Result<String, u32> {
        let signature = format!("{}{}", agent_did, agent_delegated_key);
        let signature = crypto::sign(wallet::get_wallet_handle(), to_vk, signature.as_bytes())?;
        let signature = base64::encode(&signature);
        Ok(signature.to_string())
    }
}

impl GeneralMessage for SendInvite{
    type SendSecureResult = Vec<String>;

    fn msgpack(&mut self) -> Result<Vec<u8>,u32> {
        debug!("connection invitation details: {}", serde_json::to_string(&self.payload.msg_detail_payload).unwrap_or("failure".to_string()));
        let create = encode::to_vec_named(&self.payload.create_payload).or(Err(error::UNKNOWN_ERROR.code_num))?;
        let details = encode::to_vec_named(&self.payload.msg_detail_payload).or(Err(error::UNKNOWN_ERROR.code_num))?;

        let mut bundle = Bundled::create(create);
        bundle.bundled.push(details);

        let msg = bundle.encode()?;

        bundle_for_agent(msg, &self.to_vk, &self.agent_did, &self.agent_vk)
    }

    fn send_secure(&mut self) -> Result<Self::SendSecureResult, u32> {
        let data = self.msgpack()?;

        if settings::test_agency_mode_enabled() { httpclient::set_next_u8_response(SEND_INVITE_RESPONSE.to_vec()); }

        let mut result = Vec::new();
        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => {
                let response = parse_response(response)?;
                result.push(response);
            },
        };

        Ok(result.to_owned())
    }
}

fn parse_response(response: Vec<u8>) -> Result<String, u32> {
    let data = unbundle_from_agency(response)?;

    if data.len() != 3 {
        error!("expected 3 messages (got {})", data.len());
        return Err(error::INVALID_MSGPACK.code_num);
    }
    debug!("invite details response: {:?}", data[1]);
    let mut de = Deserializer::new(&data[1][..]);
    let response: MsgDetailResponse = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("Could not parse messagepack: {}", x);
            return Err(error::INVALID_MSGPACK.code_num)
        },
    };

    debug!("Invite Details: {:?}", response.invite_detail);
    serde_json::to_string(&response.invite_detail).or(Err(error::INVALID_JSON.code_num))
}

#[cfg(test)]
mod tests {
    use super::*;
    use messages::send_invite;
    use utils::libindy::signus::create_and_store_my_did;

    #[test]
    fn test_send_invite_set_values_and_post(){
        init!("false");
        ::utils::logger::LoggerUtils::init_test_logging("trace");
        let (user_did, user_vk) = create_and_store_my_did(None).unwrap();
        let (agent_did, agent_vk) = create_and_store_my_did(Some(MY2_SEED)).unwrap();
        let (my_did, my_vk) = create_and_store_my_did(Some(MY1_SEED)).unwrap();
        let (agency_did, agency_vk) = create_and_store_my_did(Some(MY3_SEED)).unwrap();

        settings::set_config_value(settings::CONFIG_AGENCY_VERKEY, &agency_vk);
        settings::set_config_value(settings::CONFIG_REMOTE_TO_SDK_VERKEY, &agent_vk);
        settings::set_config_value(settings::CONFIG_SDK_TO_REMOTE_VERKEY, &my_vk);

        let msg = send_invite()
            .to(&user_did)
            .to_vk(&user_vk)
            .agent_did(&agent_did)
            .agent_vk(&agent_vk)
            .phone_number(&Some("phone".to_string()))
            .key_delegate("key")
            .build().unwrap()
            .msgpack().unwrap();

        assert!(msg.len() > 0);
    }

    #[test]
    fn test_parse_send_invite_response() {
        init!("indy");
        let result = parse_response(SEND_INVITE_RESPONSE.to_vec()).unwrap();

        assert_eq!(result, INVITE_DETAIL_STRING);
    }
}