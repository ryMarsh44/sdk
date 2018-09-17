extern crate rust_base58;
extern crate serde_json;
extern crate serde;
extern crate rmp_serde;

use self::rmp_serde::encode;
use settings;
use utils::httpclient;
use utils::error;
use messages::*;
use serde::Deserialize;
use self::rmp_serde::Deserializer;



#[derive(Serialize, Deserialize)]
pub struct CreateKeyResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "withPairwiseDID")]
    for_did: String,
    #[serde(rename = "withPairwiseDIDVerKey")]
    for_verkey: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct CreateKeyPayload{
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "forDID")]
    for_did: String,
    #[serde(rename = "forDIDVerKey")]
    for_verkey: String,
}

#[derive(Serialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyMsg {
    #[serde(rename = "to")]
    to_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_vk: Option<String>,
    agent_did: Option<String>,
    agent_vk: Option<String>,
    agent_payload: String,
    #[serde(skip_serializing, default)]
    payload: CreateKeyPayload,
}

pub struct CreateKeyMsgBuilder {
    to_did: Option<Result<String, u32>>,
    to_vk: Option<Result<String, u32>>,
    agent_did: Option<Result<String, u32>>,
    agent_vk: Option<Result<String, u32>>,
    for_did: Option<Result<String, u32>>,
    for_vk: Option<Result<String, u32>>,
}

impl MsgUtils for CreateKeyMsgBuilder {}
impl GeneralMessageBuilder for CreateKeyMsgBuilder {
    type MsgBuilder = CreateKeyMsgBuilder;
    type Msg = CreateKeyMsg;

    fn new() -> CreateKeyMsgBuilder {
        CreateKeyMsgBuilder {
            to_did: None,
            to_vk: None,
            agent_did: None,
            agent_vk: None,
            for_did: None,
            for_vk: None,
        }
    }

    fn to(mut self, did: &str) -> CreateKeyMsgBuilder {
        self.to_did = Some(validation::validate_did(did));
        self
    }

    fn to_vk(mut self, vk: &str) -> CreateKeyMsgBuilder {
        self.to_vk = Some(validation::validate_verkey(vk));
        self
    }

    fn agent_did(mut self, did: &str) -> CreateKeyMsgBuilder {
        self.agent_did = Some(validation::validate_did(did));
        self
    }

    fn agent_vk(mut self, vk: &str) -> CreateKeyMsgBuilder {
        self.agent_vk = Some(validation::validate_verkey(vk));
        self
    }

    fn build(self) -> Result<CreateKeyMsg, u32> {
        let build_err = error::MISSING_MSG_FIELD.code_num;

        Ok(CreateKeyMsg {
            to_did: self.to_did.clone().ok_or(build_err)??,
            to_vk: self.optional_field(self.to_vk.clone())?,
            agent_did: self.optional_field(self.agent_did.clone())?,
            agent_vk: self.optional_field(self.agent_vk.clone())?,
            payload: CreateKeyPayload {
                msg_type: MsgType { name: "CREATE_KEY".to_string(), ver: "1.0".to_string()},
                for_did: self.for_did.clone().ok_or(build_err)??,
                for_verkey: self.for_vk.clone().ok_or(build_err)??,
            },
            agent_payload: String::new(),
        })
    }
}

impl CreateKeyMsgBuilder {
    pub fn for_did(mut self, did: &str) -> CreateKeyMsgBuilder {
        self.for_did = Some(validation::validate_did(did));
        self
    }

    pub fn for_verkey(mut self, vk: &str) -> CreateKeyMsgBuilder {
        self.for_vk = Some(validation::validate_verkey(vk));
        self
    }
}

//Todo: Every GeneralMessage extension, duplicates code
impl GeneralMessage for CreateKeyMsg  {
    type SendSecureResult = Vec<String>;
    fn msgpack(&mut self) -> Result<Vec<u8>,u32> {
        let data = encode::to_vec_named(&self.payload)
            .map_err(|e| {
                error!("could not encode create_keys msg: {}", e);
                error::INVALID_MSGPACK.code_num
            })?;

        debug!("create_keys inner bundle: {:?}", data);
        let msg = Bundled::create(data).encode()?;

        bundle_for_agency(msg, &self.to_did)
    }

    fn send_secure(&mut self) -> Result<Vec<String>, u32> {
        let data = self.msgpack()?;

        if settings::test_agency_mode_enabled() {
            return Ok(vec!["U5LXs4U7P9msh647kToezy".to_string(), "FktSZg8idAVzyQZrdUppK6FTrfAzW3wWVzAjJAfdUvJq".to_string()]);
        }

        let mut result = Vec::new();
        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => {
                let (did, vk) = parse_create_keys_response(response)?;
                result.push(did);
                result.push(vk);
            },
        };

        Ok(result.to_owned())
    }
}

pub fn parse_create_keys_response(response: Vec<u8>) -> Result<(String, String), u32> {
    let data = unbundle_from_agency(response)?;

    debug!("create keys response inner bundle: {:?}", data[0]);
    let mut de = Deserializer::new(&data[0][..]);
    let response: CreateKeyResponse = Deserialize::deserialize(&mut de).or(Err(error::UNKNOWN_ERROR.code_num))?;

    Ok((response.for_did, response.for_verkey))
}


#[cfg(test)]
mod tests {
    use super::*;
    use utils::constants::{ CREATE_KEYS_RESPONSE, MY1_SEED, MY2_SEED, MY3_SEED };
    use utils::libindy::signus::create_and_store_my_did;
    use messages::create_keys;

    #[test]
    fn test_create_key_set_values() {
        let to_did = "8XFh8yBzrpJQmNyZzgoTqB";
        let for_did = "11235yBzrpJQmNyZzgoTqB";
        let for_verkey = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        let msg_payload = CreateKeyPayload {
            for_did: for_did.to_string(),
            for_verkey: for_verkey.to_string(),
            msg_type: MsgType { name: "CREATE_KEY".to_string(), ver: "1.0".to_string(), } ,
        };
        let msg = create_keys()
            .to(to_did)
            .for_did(for_did)
            .for_verkey(for_verkey)
            .agent_did(to_did)
            .agent_vk(for_verkey)
            .build().unwrap();
        assert_eq!(msg.payload, msg_payload);
    }

    #[test]
    fn test_create_key_set_values_and_serialize() {
        init!("false");

        let (agent_did, agent_vk) = create_and_store_my_did(Some(MY2_SEED)).unwrap();
        let (my_did, my_vk) = create_and_store_my_did(Some(MY1_SEED)).unwrap();
        let (agency_did, agency_vk) = create_and_store_my_did(Some(MY3_SEED)).unwrap();

        settings::set_config_value(settings::CONFIG_AGENCY_VERKEY, &agency_vk);
        settings::set_config_value(settings::CONFIG_REMOTE_TO_SDK_VERKEY, &agent_vk);
        settings::set_config_value(settings::CONFIG_SDK_TO_REMOTE_VERKEY, &my_vk);

        let bytes = create_keys()
            .to(&agent_did)
            .for_did(&my_did)
            .for_verkey(&my_vk)
            .build().unwrap()
            .msgpack().unwrap();
        assert!(bytes.len() > 0);
    }

    #[test]
    fn test_parse_create_keys_response() {
        init!("true");

        let result = parse_create_keys_response(CREATE_KEYS_RESPONSE.to_vec()).unwrap();

        assert_eq!(result.0, "U5LXs4U7P9msh647kToezy");
        assert_eq!(result.1, "FktSZg8idAVzyQZrdUppK6FTrfAzW3wWVzAjJAfdUvJq");
    }
}

