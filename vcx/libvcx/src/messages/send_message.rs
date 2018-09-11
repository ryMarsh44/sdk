extern crate rust_base58;
extern crate serde_json;
extern crate serde;
extern crate rmp_serde;

use settings;
use utils::httpclient;
use utils::error;
use serde::Deserialize;
use self::rmp_serde::Deserializer;
use messages::*;

/*
pub struct SendMessage {
message: Option<String>,
agent_payload: Option<String>,
status_code: Option<String>,
uid: Option<String>,
title: Option<String>,
detail: Option<String>,
}
*/
pub struct SendMessage {
    message: String,
    to_did: String,
    to_vk: String,
    agent_did:  String,
    agent_vk: String,
    payload: Vec<u8>,
    uid: Option<String>,
    agent_payload: Option<String>,
    ref_msg_id: Option<String>,
    status_code: Option<String>,
    title: Option<String>,
    detail: Option<String>,
}

#[derive(Serialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessagePayload {
    #[serde(rename = "@type")]
    pub msg_type: MsgType,
    pub mtype: String,
    #[serde(rename = "replyToMsgId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_msg_id: Option<String>,
    pub send_msg: bool,
}

#[derive(Serialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageDetailPayload {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "@msg")]
    msg: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

pub struct SendMessageBuilder {
    message: Option<Result<String, u32>>,
    to_did: Option<Result<String, u32>>,
    to_vk: Option<Result<String, u32>>,
    agent_did:  Option<Result<String, u32>>,
    agent_vk:  Option<Result<String, u32>>,
    agent_payload:  Option<Result<String, u32>>,
    payload:  Option<Result<Vec<u8>, u32>>,
    ref_msg_id: Option<Result<String, u32>>,
    status_code: Option<Result<String, u32>>,
    uid: Option<Result<String, u32>>,
    title: Option<Result<String, u32>>,
    detail: Option<Result<String, u32>>,
}

impl MsgUtils for SendMessageBuilder {}
impl GeneralMessageBuilder for SendMessageBuilder {
    type MsgBuilder = SendMessageBuilder;
    type Msg = SendMessage;

    fn to(mut self, did: &str) -> SendMessageBuilder {
        self.to_did = Some(validation::validate_did(did));
        self
    }

    fn to_vk(mut self, vk: &str) -> SendMessageBuilder {
        self.to_vk = Some(validation::validate_verkey(vk));
        self
    }

    fn agent_did(mut self, did: &str) -> SendMessageBuilder {
        self.agent_did = Some(validation::validate_did(did));
        self
    }

    fn agent_vk(mut self, vk: &str) -> SendMessageBuilder {
        self.agent_vk = Some(validation::validate_verkey(vk));
        self
    }
    fn build(self) -> Result<SendMessage, u32> {
        Ok(SendMessage {
            message: self.mandatory_field(self.message.clone())?,
            to_did: self.mandatory_field(self.to_did.clone())?,
            to_vk: self.mandatory_field(self.to_vk.clone())?,
            agent_did: self.mandatory_field(self.agent_did.clone())?,
            agent_vk: self.mandatory_field(self.agent_vk.clone())?,
            payload: self.mandatory_field(self.payload.clone())?,
            agent_payload: self.optional_field(self.agent_payload.clone())?,
            ref_msg_id: self.optional_field(self.ref_msg_id.clone())?,
            status_code: self.optional_field(self.status_code.clone())?,
            uid: self.optional_field(self.uid.clone())?,
            title: self.optional_field(self.title.clone())?,
            detail: self.optional_field(self.detail.clone())?,
        })
    }
}

impl SendMessageBuilder{

    pub fn new() -> SendMessageBuilder {
        SendMessageBuilder {
            message: None,
            to_did: None,
            to_vk: None,
            agent_did:  None,
            agent_vk:  None,
            agent_payload:  None,
            payload:  None,
            ref_msg_id: None,
            status_code: None,
            uid: None,
            title: None,
            detail: None,
        }
    }

    pub fn msg_type(mut self, msg: &str) -> SendMessageBuilder{
        self.message = self.wrap_ok(msg.to_string());
        self
    }

    pub fn uid(mut self, uid: &str) -> SendMessageBuilder{
        self.uid = self.wrap_ok(uid.to_string());
        self
    }

    pub fn status_code(mut self, code: &str) -> SendMessageBuilder {
        self.status_code = self.wrap_ok(code.to_string());
        self
    }


    pub fn edge_agent_payload(mut self, payload: &Vec<u8>) -> SendMessageBuilder {
        self.payload = self.wrap_ok(payload.clone());
        self
    }

    pub fn ref_msg_id(mut self, id: &str) -> SendMessageBuilder {
        self.ref_msg_id = self.wrap_ok(id.to_string());
        self
    }


    pub fn set_title(mut self, title: &str) -> SendMessageBuilder {
        self.title = self.wrap_ok(title.to_string());
        self
    }

    pub fn set_detail(mut self, detail: &str) -> SendMessageBuilder {
        self.detail = self.wrap_ok(detail.to_string());
        self
    }
}

impl GeneralMessage2 for SendMessage {
    fn msgpack(&mut self) -> Result<Vec<u8>, u32> {

        let create = CreateMessagePayload { msg_type: MsgType { name: "CREATE_MSG".to_string(), ver: "1.0".to_string(), }, mtype: self.message.to_string(), reply_to_msg_id: self.ref_msg_id.clone(), send_msg: true};
        let detail = MessageDetailPayload { msg_type: MsgType { name: "MSG_DETAIL".to_string(), ver: "1.0".to_string(), }, msg: self.payload.clone(), title: self.title.clone(), detail: self.detail.clone(), };

        match serde_json::to_string(&detail) {
            Ok(x) => debug!("sending message: {}", x),
            Err(_) => {},
        };

        debug!("SendMessage details: {:?}", detail);
        let create = encode::to_vec_named(&create).unwrap();
        let detail = encode::to_vec_named(&detail).unwrap();

        let mut bundle = Bundled::create(create);
        bundle.bundled.push(detail);

        let msg = bundle.encode()?;
        bundle_for_agent(msg, &self.to_vk, &self.agent_did, &self.agent_vk)
    }
}

impl SendMessage{
    pub fn send_secure(&mut self) -> Result<Vec<String>, u32> {
        let data = match self.msgpack() {
            Ok(x) => x,
            Err(x) => return Err(x),
        };

        let mut result = Vec::new();
        debug!("sending secure message to agency");
        if settings::test_agency_mode_enabled() {
            result.push(parse_send_message_response(::utils::constants::SEND_MESSAGE_RESPONSE.to_vec())?);
            return Ok(result.to_owned());
        }

        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => result.push(parse_send_message_response(response)?),
        };
        debug!("sent message to agency");
        Ok(result.to_owned())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    uids: Vec<String>,
}

fn parse_send_message_response(response: Vec<u8>) -> Result<String, u32> {
    let data = unbundle_from_agency(response)?;

    if data.len() <= 1 {
        return Err(error::INVALID_HTTP_RESPONSE.code_num);
    }

    let mut de = Deserializer::new(&data[1][..]);
    let response: SendMessageResponse = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("Could not parse messagepack: {}", x);
            return Err(error::INVALID_MSGPACK.code_num)
        },
    };

    debug!("messages: {:?}", response);
    match serde_json::to_string(&response) {
        Ok(x) => Ok(x),
        Err(_) => Err(error::INVALID_JSON.code_num),
    }
}


pub fn parse_msg_uid(response: &str) -> Result<String,u32> {
    match serde_json::from_str(response) {
        Ok(json) => {
            let json: serde_json::Value = json;
            match json["uids"].as_array() {
                Some(x) => {
                    Ok(String::from(x[0].as_str().unwrap()))
                },
                None => {
                    info!("response had no uid");
                    Err(error::INVALID_JSON.code_num)
                },
            }

        },
        Err(_) => {
            info!("get_messages called without a valid response from server");
            Err(error::INVALID_JSON.code_num)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::constants::SEND_MESSAGE_RESPONSE;

    fn populated_send_msg_builder() -> SendMessageBuilder {
        let local_my_did = "8XFh8yBzrpJQmNyZzgoTqB";
        let local_my_vk = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let msg_type = "";
        let agent_did = "8XFh8yBzrpJQmNyZzgoTzz";
        let agent_vk = "BBBBa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let data = vec![1,2,3,4,5,6,7,8];
        let ref_msg_id = "123";
        SendMessageBuilder::new()
            .to(local_my_did)
            .to_vk(local_my_vk)
            .msg_type(msg_type)
            .agent_did(agent_did)
            .agent_vk(agent_vk)
            .edge_agent_payload(&data)
            .ref_msg_id(ref_msg_id)
    }

    #[test]
    fn test_msgpack() {
        settings::set_defaults();
        settings::set_config_value(settings::CONFIG_ENABLE_TEST_MODE, "true");
        let mut message = populated_send_msg_builder().build().unwrap();


        /* just check that it doesn't panic */
        let packed = message.msgpack().unwrap();
    }

    #[test]
    fn test_parse_send_message_response() {
        settings::set_defaults();
        settings::set_config_value(settings::CONFIG_ENABLE_TEST_MODE, "true");
        let result = parse_send_message_response(SEND_MESSAGE_RESPONSE.to_vec()).unwrap();

        assert_eq!("{\"@type\":{\"name\":\"MSG_SENT\",\"ver\":\"1.0\"},\"uids\":[\"ntc2ytb\"]}", result);
    }

    /*
    #[test]
    fn test_parse_send_message_bad_response() {
        settings::set_defaults();
        settings::set_config_value(settings::CONFIG_ENABLE_TEST_MODE, "true");
        let result = parse_send_message_response(::utils::constants::UPDATE_PROFILE_RESPONSE.to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_msg_uid() {

        let test_val = "devin";
        let test_json = json!({
            "uids": [test_val]
        });

        let to_str = serde_json::to_string(&test_json).unwrap();
        let uid = parse_msg_uid(&to_str).unwrap();
        assert_eq!(test_val, uid);

        let test_val = "devin";
        let test_json = json!({
            "uids": "test_val"
        });

        let to_str = serde_json::to_string(&test_json).unwrap();
        let uid = parse_msg_uid(&to_str).unwrap_err();
        assert_eq!(error::INVALID_JSON.code_num, uid);

        let test_val = "devin";
        let test_json = json!({});

        let to_str = serde_json::to_string(&test_json).unwrap();
        let uid = parse_msg_uid(&to_str).unwrap_err();
        assert_eq!(error::INVALID_JSON.code_num, uid);
    }*/
}
