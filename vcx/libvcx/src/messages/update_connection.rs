extern crate rmp_serde;
extern crate serde_json;

use error::{ToErrorCode, messages};
use serde::Deserialize;
use self::rmp_serde::{encode, Deserializer};
use messages::{Bundled, MsgType, bundle_for_agent, unbundle_from_agency, GeneralMessage, MsgUtils, GeneralMessageBuilder};
use messages::validation;
use utils::{error, httpclient};
use settings;
use utils::constants::DELETE_CONNECTION_RESPONSE;

#[derive(Clone,Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct DeleteConnectionPayload{
    #[serde(rename = "@type")]
    msg_type: MsgType,
    status_code: String,

}

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct DeleteConnection {
    #[serde(rename = "to")]
    to_did: String,
    to_vk: String,
    agent_did: String,
    agent_vk: String,
    #[serde(skip_serializing, default)]
    payload: DeleteConnectionPayload,
}

pub struct DeleteConnectionBuilder {
    to_did: Option<Result<String, u32>>,
    to_vk: Option<Result<String, u32>>,
    agent_did: Option<Result<String, u32>>,
    agent_vk: Option<Result<String, u32>>,
}

impl MsgUtils for DeleteConnectionBuilder {}
impl GeneralMessageBuilder for DeleteConnectionBuilder {
    type MsgBuilder = DeleteConnectionBuilder;
    type Msg = DeleteConnection;

    fn new() -> DeleteConnectionBuilder {
        DeleteConnectionBuilder {
            to_did: None,
            to_vk: None,
            agent_did: None,
            agent_vk: None,
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
        self
    }

    fn build(self) -> Result<Self::Msg, u32> {
        let build_err = error::MISSING_MSG_FIELD.code_num;

        Ok(DeleteConnection {
            to_did: self.to_did.clone().ok_or(build_err)??,
            to_vk: self.to_vk.clone().ok_or(build_err)??,
            agent_did: self.agent_did.clone().ok_or(build_err)??,
            agent_vk: self.agent_vk.clone().ok_or(build_err)??,
            payload: DeleteConnectionPayload::create(),
        })
    }
}

impl DeleteConnection {
    pub fn parse_response_as_delete_connection_payload(&self, response: &Vec<u8> ) -> Result<String, u32> {
        if settings::test_agency_mode_enabled() {
            let data = response.clone();
            return Ok(serde_json::to_string(&DeleteConnectionPayload::deserialize(data.to_owned()).unwrap()).unwrap())
        }
        let data = unbundle_from_agency(response.clone())?;
        let response = DeleteConnectionPayload::deserialize(data[0].to_owned())
            .map_err(|e| e.to_error_code())?;
        serde_json::to_string(&response).or(Err(error::INVALID_JSON.code_num))
    }
}

impl GeneralMessage for DeleteConnection{
    type SendSecureResult = Vec<String>;

    fn msgpack(&mut self) -> Result<Vec<u8>,u32> {
        let payload = encode::to_vec_named(&self.payload).or(Err(error::INVALID_JSON.code_num))?;

        let bundle = Bundled::create(payload);

        let msg = bundle.encode()?;

        bundle_for_agent(msg, &self.to_vk, &self.agent_did, &self.agent_vk)
    }

    fn send_secure(&mut self) -> Result<Self::SendSecureResult, u32> {
        let data = self.msgpack()?;

        if settings::test_agency_mode_enabled() { httpclient::set_next_u8_response(DELETE_CONNECTION_RESPONSE.to_vec()); }

        let mut result = Vec::new();
        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => {
                let response = self.parse_response_as_delete_connection_payload(&response)?;
                result.push(response);
            },
        };

        Ok(result.to_owned())
    }
}

impl DeleteConnectionPayload {
    pub fn create() -> DeleteConnectionPayload {
        DeleteConnectionPayload {
            msg_type: MsgType {
                name: "UPDATE_CONN_STATUS".to_string(),
                ver: "1.0".to_string()
            },
            status_code: "CS-103".to_string(),
        }
    }

    pub fn deserialize(data: Vec<u8>) ->
    Result< DeleteConnectionPayload,
        messages::MessageError> {
        let mut de = Deserializer::new(&data[..]);
        let message: Self = match Deserialize::deserialize(&mut de) {
            Ok(x) => x,
            Err(x) => {
                return Err(messages::MessageError::MessagePackError())
            },
        };
        Ok(message)

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_deserialize_delete_connection_payload(){
        let payload = vec![130, 165, 64, 116, 121, 112, 101, 130, 164, 110, 97, 109, 101, 179, 67, 79, 78, 78, 95, 83, 84, 65, 84, 85, 83, 95, 85, 80, 68, 65, 84, 69, 68, 163, 118, 101, 114, 163, 49, 46, 48, 170, 115, 116, 97, 116, 117, 115, 67, 111, 100, 101, 166, 67, 83, 45, 49, 48, 51];
        let msg_str = r#"{ "@type": { "name": "CONN_STATUS_UPDATED", "ver": "1.0" }, "statusCode": "CS-103" }"#;
        let delete_connection_payload: DeleteConnectionPayload = serde_json::from_str(msg_str).unwrap();
        assert_eq!(delete_connection_payload, DeleteConnectionPayload::deserialize(payload.clone()).unwrap());

        let to_did = "8XFh8yBzrpJQmNyZzgoTqB";
        let to_vk = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let agent_did = "8XFh8yBzrpJQmNyZzgoTzz";
        let agent_vk = "BBBBa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let delete: DeleteConnection = DeleteConnectionBuilder::new()
            .to(to_did)
            .to_vk(to_vk)
            .agent_did(agent_did)
            .agent_vk(agent_vk)
            .build().unwrap();
    }
}