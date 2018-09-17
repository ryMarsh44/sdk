extern crate rust_base58;
extern crate serde_json;
extern crate serde;
extern crate rmp_serde;

use settings;
use utils::httpclient;
use utils::error;
use messages::*;
use messages::MessageResponseCode::{ MessageAccepted, MessagePending };
use utils::libindy::crypto;

#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct GetMessagesPayload{
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "excludePayload")]
    #[serde(skip_serializing_if = "Option::is_none")]
    exclude_payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_codes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pairwiseDIDs")]
    pairwise_dids: Option<Vec<String>>,
}

//Todo: to_did, agent_did, agent_vk are required for .send_secure but not for download. SPlit up message?
#[derive(Serialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetMessages {
    #[serde(rename = "to")]
    to_did: Option<String>,
    agent_payload: Option<String>,
    #[serde(skip_serializing, default)]
    payload: GetMessagesPayload,
    #[serde(skip_serializing, default)]
    to_vk: Option<String>,
    #[serde(skip_serializing, default)]
    agent_did: Option<String>,
    #[serde(skip_serializing, default)]
    agent_vk: Option<String>,
}

pub struct GetMessagesBuilder {
    to_did: Option<Result<String, u32>>,
    agent_payload: Option<Result<String, u32>>,
    to_vk: Option<Result<String, u32>>,
    agent_did: Option<Result<String, u32>>,
    agent_vk: Option<Result<String, u32>>,
    msg_type: Option<MsgType>,
    exclude_payload: Option<String>,
    uids: Option<Vec<String>>,
    status_codes: Option<Vec<String>>,
    pairwise_dids: Option<Vec<String>>,

}

impl MsgUtils for GetMessagesBuilder {}
impl GeneralMessageBuilder for GetMessagesBuilder {
    type MsgBuilder = GetMessagesBuilder;
    type Msg = GetMessages;

    fn new() -> GetMessagesBuilder {
        GetMessagesBuilder {
            to_did: None,
            agent_payload: None,
            to_vk: None,
            agent_did: None,
            agent_vk: None,
            msg_type: None,
            exclude_payload: None,
            uids: None,
            status_codes: None,
            pairwise_dids: None,
        }
    }

    fn to(mut self, did: &str) -> GetMessagesBuilder {
        self.to_did = Some(validation::validate_did(did));
        self
    }

    fn to_vk(mut self, vk: &str) -> GetMessagesBuilder {
        self.to_vk = Some(validation::validate_verkey(vk));
        self
    }

    fn agent_did(mut self, did: &str) -> GetMessagesBuilder {
        self.agent_did = Some(validation::validate_did(did));
        self
    }

    fn agent_vk(mut self, vk: &str) -> GetMessagesBuilder {
        self.agent_vk = Some(validation::validate_verkey(vk));
        self
    }
    fn build(self) -> Result<GetMessages, u32> {
        Ok(GetMessages {
            to_did: self.optional_field(self.to_did.clone())?,
            to_vk: self.optional_field(self.to_vk.clone())?,
            agent_did: self.optional_field(self.agent_did.clone())?,
            agent_vk: self.optional_field(self.agent_vk.clone())?,
            agent_payload: self.optional_field(self.agent_payload.clone())?,
            payload: GetMessagesPayload {
                msg_type: MsgType { name: "GET_MSGS".to_string(), ver: "1.0".to_string() },
                exclude_payload: self.exclude_payload,
                uids: self.uids,
                status_codes: self.status_codes,
                pairwise_dids: self.pairwise_dids,
            }
        })
    }
}

impl GetMessagesBuilder{

    pub fn uid(mut self, uids: Option<Vec<String>>) -> GetMessagesBuilder {
        self.uids = uids;
        self
    }

    pub fn status_codes(mut self, status_codes: Option<Vec<String>>) -> GetMessagesBuilder {
        self.status_codes = status_codes;
        self
    }

    pub fn pairwise_dids(mut self, pairwise_dids: Option<Vec<String>>) -> GetMessagesBuilder {
        self.pairwise_dids = pairwise_dids;
        self
    }

    pub fn include_edge_payload(mut self, payload: &str) -> GetMessagesBuilder {
        self.exclude_payload = Some(payload.to_string());
        self
    }
}

impl GeneralMessage for GetMessages{
    type SendSecureResult = Vec<Message>;
    fn msgpack(&mut self) -> Result<Vec<u8>,u32> {
        let data = encode::to_vec_named(&self.payload).or(Err(error::UNKNOWN_ERROR.code_num))?;
        trace!("get_message content: {:?}", data);

        let msg = Bundled::create(data).encode()?;

        bundle_for_agent(
            msg,
            self.to_vk.as_ref().ok_or(error::MISSING_MSG_FIELD.code_num)?,
            self.agent_did.as_ref().ok_or(error::MISSING_MSG_FIELD.code_num)?,
            self.agent_vk.as_ref().ok_or(error::MISSING_MSG_FIELD.code_num)?
        )
    }

    fn send_secure(&mut self) -> Result<Vec<Message>, u32> {
        let data = self.msgpack()?;

        match httpclient::post_u8(&data) {
            Ok(response) => if settings::test_agency_mode_enabled() && response.len() == 0 {
                return Ok(Vec::new());
            } else {
                parse_get_messages_response(response)
            },
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
        }
    }
}

impl GetMessages{
    pub fn download_messages(&mut self) -> Result<Vec<ConnectionMessages>, u32> {
        self.payload.msg_type.name = "GET_MSGS_BY_CONNS".to_string();
        let data = encode::to_vec_named(&self.payload).or(Err(error::UNKNOWN_ERROR.code_num))?;
        trace!("get_message content: {:?}", data);

        let msg = Bundled::create(data).encode()?;

        let to_did = settings::get_config_value(settings::CONFIG_REMOTE_TO_SDK_DID)?;

        let data = bundle_for_agency(msg, &to_did)?;

        match httpclient::post_u8(&data) {
            Err(_) => return Err(error::POST_MSG_FAILURE.code_num),
            Ok(response) => if settings::test_agency_mode_enabled() && response.len() == 0 {
                return Ok(Vec::new());
            } else {
                parse_get_connection_messages_response(response)
            },
        }
    }
}


#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetMsgType {
    pub name: String,
    pub ver: String,
    pub fmt: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetMsgResponse {
    #[serde(rename = "@type")]
    pub msg_type: GetMsgType,
    #[serde(rename = "@msg")]
    pub msg: Vec<i8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryDetails {
    to: String,
    status_code: String,
    last_updated_date_time: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub status_code: String,
    pub payload: Option<Vec<i8>>,
    #[serde(rename = "senderDID")]
    pub sender_did: String,
    pub uid: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub ref_msg_id: Option<String>,
    #[serde(skip_deserializing)]
    pub delivery_details: Vec<DeliveryDetails>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypted_payload: Option<String>,
}

impl Message {
    pub fn new() -> Message {
        Message {
            status_code: String::new(),
            payload: None,
            sender_did: String::new(),
            uid: String::new(),
            msg_type: String::new(),
            ref_msg_id: None,
            delivery_details: Vec::new(),
            decrypted_payload: None,
        }    
    }

    pub fn decrypt(&self, vk: &str) -> Message {
        let mut new_message = self.clone();
        if let Some(ref payload) = self.payload {
            let payload = ::messages::to_u8(payload);
            match ::utils::libindy::crypto::parse_msg(&vk, &payload) {
                Ok(x) => {
                    new_message.decrypted_payload = to_json(&x.1)
                        .map(|i| i.to_string())
                        .ok();
                }
                Err(_) => (),
            };
        }
        new_message.payload = None;
        new_message
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetMessagesResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    msgs: Vec<Message>,
}

fn parse_get_messages_response(response: Vec<u8>) -> Result<Vec<Message>, u32> {
    let data = unbundle_from_agency(response)?;

    trace!("get_message response: {:?}", data[0]);
    let mut de = Deserializer::new(&data[0][..]);
    let response: GetMessagesResponse = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("Could not parse messagepack: {}", x);

            return Err(error::INVALID_MSGPACK.code_num)
        },
    };

    Ok(response.msgs.to_owned())
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetConnectionMessagesResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    msgs_by_conns: Vec<ConnectionMessages>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
pub struct ConnectionMessages {
    #[serde(rename = "pairwiseDID")]
    pub pairwise_did: String,
    pub msgs: Vec<Message>,
}

fn parse_get_connection_messages_response(response: Vec<u8>) -> Result<Vec<ConnectionMessages>, u32> {
    let data = unbundle_from_agency(response)?;

    trace!("parse_get_connection_message response: {:?}", data[0]);
    let mut de = Deserializer::new(&data[0][..]);
    let response: GetConnectionMessagesResponse = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("Could not parse messagepack: {}", x);

            return Err(error::INVALID_MSGPACK.code_num)
        },
    };

    let mut connection_messages = Vec::new();
    for connection in response.msgs_by_conns.iter() {
        let vk = ::utils::libindy::signus::get_local_verkey(&connection.pairwise_did)?;
        let mut new_messages = Vec::new();
        for message in connection.msgs.iter() {
            new_messages.push(message.decrypt(&vk));
        }
        connection_messages.push(ConnectionMessages {
            pairwise_did: connection.pairwise_did.clone(),
            msgs: new_messages,
        })
    }
    Ok(connection_messages)
}

pub fn get_connection_messages(pw_did: &str, pw_vk: &str, agent_did: &str, agent_vk: &str, msg_uid: Option<Vec<String>>) -> Result<Vec<Message>, u32> {

    match get_messages()
        .to(&pw_did)
        .to_vk(&pw_vk)
        .agent_did(&agent_did)
        .agent_vk(&agent_vk)
        .uid(msg_uid)
        .build()?
        .send_secure() {
        Err(x) => {
            error!("could not post get_messages: {}", x);
            Err(error::POST_MSG_FAILURE.code_num)
        },
        Ok(response) => {
            if response.len() == 0 {
                Err(error::POST_MSG_FAILURE.code_num)
            } else {
                trace!("message returned: {:?}", response[0]);
                Ok(response)
            }
        },
    }
}

pub fn get_ref_msg(msg_id: &str, pw_did: &str, pw_vk: &str, agent_did: &str, agent_vk: &str) -> Result<(String, Vec<u8>), u32> {
    let message = get_connection_messages(pw_did, pw_vk, agent_did, agent_vk, Some(vec![msg_id.to_string()]))?;
    trace!("checking for ref_msg: {:?}", message);

    let msg_id = match message[0].ref_msg_id.clone() {
        Some(ref ref_msg_id) if message[0].status_code == MessageAccepted.as_string() => ref_msg_id.to_string(),
        _ => return Err(error::NOT_READY.code_num),
    };

    let message = get_connection_messages(pw_did, pw_vk, agent_did, agent_vk, Some(vec![msg_id]))?;

    trace!("checking for pending message: {:?}", message);

    // this will work for both credReq and proof types
    match message[0].payload.clone() {
        Some(ref payload) if message[0].status_code == MessagePending.as_string() => {
            // TODO: check returned verkey
            let (_, msg) = crypto::parse_msg(&pw_vk, &to_u8(payload))?;
            Ok((message[0].uid.clone(), msg))
        },
        _ => Err(error::INVALID_HTTP_RESPONSE.code_num)
    }
}

pub fn download_messages(pairwise_dids: Option<Vec<String>>, status_codes: Option<Vec<String>>, uids: Option<Vec<String>>) -> Result<Vec<ConnectionMessages>, u32> {

    if settings::test_agency_mode_enabled() {
        ::utils::httpclient::set_next_u8_response(::utils::constants::GET_ALL_MESSAGES_RESPONSE.to_vec());
    }

    match get_messages()
        .uid(uids)
        .status_codes(status_codes)
        .pairwise_dids(pairwise_dids)
        .build()?
        .download_messages() {
        Err(x) => {
            error!("could not post get_messages: {}", x);
            Err(error::POST_MSG_FAILURE.code_num)
        },
        Ok(response) => {
            trace!("message returned: {:?}", response[0]);
            Ok(response)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::constants::{GET_MESSAGES_RESPONSE, GET_ALL_MESSAGES_RESPONSE};

    #[test]
    fn test_parse_get_messages_response() {
        init!("true");

        let result = parse_get_messages_response(GET_MESSAGES_RESPONSE.to_vec()).unwrap();
        assert_eq!(result.len(), 3)
    }

    #[test]
    fn test_parse_get_connection_messages_response() {
        init!("true");

        let json = to_json(&GET_ALL_MESSAGES_RESPONSE.to_vec()).unwrap();
        let result = parse_get_connection_messages_response(GET_ALL_MESSAGES_RESPONSE.to_vec()).unwrap();
        assert_eq!(result.len(), 1)
    }

    #[test]
    fn test_build_response() {
        init!("true");
        let delivery_details1 = DeliveryDetails {
            to: "3Xk9vxK9jeiqVaCPrEQ8bg".to_string(),
            status_code: "MDS-101".to_string(),
            last_updated_date_time: "2017-12-14T03:35:20.444Z[UTC]".to_string(),
        };

        let delivery_details2 = DeliveryDetails {
            to: "3Xk9vxK9jeiqVaCPrEQ8bg".to_string(),
            status_code: "MDS-101".to_string(),
            last_updated_date_time: "2017-12-14T03:35:20.500Z[UTC]".to_string(),
        };

        let msg1 = Message {
            status_code: MessageResponseCode::MessageAccepted.as_string(),
            payload: Some(vec![-9, 108, 97, 105, 109, 45, 100, 97, 116, 97]),
            sender_did: "WVsWVh8nL96BE3T3qwaCd5".to_string(),
            uid: "mmi3yze".to_string(),
            msg_type: "connReq".to_string(),
            ref_msg_id: None,
            delivery_details: vec![delivery_details1],
            decrypted_payload: None,
        };
        let msg2 = Message {
            status_code: MessageResponseCode::MessageCreate.as_string(),
            payload: None,
            sender_did: "WVsWVh8nL96BE3T3qwaCd5".to_string(),
            uid: "zjcynmq".to_string(),
            msg_type: "credOffer".to_string(),
            ref_msg_id: None,
            delivery_details: Vec::new(),
            decrypted_payload: None,
        };
        let response = GetMessagesResponse {
            msg_type: MsgType { name: "MSGS".to_string(), ver: "1.0".to_string(), },
            msgs: vec![msg1, msg2],
        };

        let data = encode::to_vec_named(&response).unwrap();

        println!("generated response: {:?}", data);
        let bundle = Bundled::create(data).encode().unwrap();
        println!("bundle: {:?}", bundle);
        let result = parse_get_messages_response(bundle).unwrap();
        println!("response: {:?}", result);
    }

    #[cfg(feature = "agency")]
    #[cfg(feature = "pool_tests")]
    #[test]
    fn test_download_messages() {
        use std::thread;
        use std::time::Duration;

        init!("agency");
        let institution_did = settings::get_config_value(settings::CONFIG_INSTITUTION_DID).unwrap();
        let (faber, alice) = ::connection::tests::create_connected_connections();

        let (schema_id, _, cred_def_id, _) = ::utils::libindy::anoncreds::tests::create_and_store_credential_def();
        let credential_data = r#"{"address1": ["123 Main St"], "address2": ["Suite 3"], "city": ["Draper"], "state": ["UT"], "zip": ["84000"]}"#;
        let credential_offer = ::issuer_credential::issuer_credential_create(cred_def_id.clone(),
                                                                           "1".to_string(),
                                                                           institution_did.clone(),
                                                                           "credential_name".to_string(),
                                                                           credential_data.to_owned(),
                                                                           1).unwrap();
        ::issuer_credential::send_credential_offer(credential_offer, alice).unwrap();
        thread::sleep(Duration::from_millis(2000));
        // AS CONSUMER GET MESSAGES
        ::utils::devsetup::tests::set_consumer();
        let all_messages = download_messages(None, None, None).unwrap();
        println!("{}", serde_json::to_string(&all_messages).unwrap());
        let pending = download_messages(None, Some(vec!["MS-103".to_string()]), None).unwrap();
        assert_eq!(pending.len(), 1);
        let accepted = download_messages(None, Some(vec!["MS-104".to_string()]), None).unwrap();
        assert_eq!(accepted[0].msgs.len(), 2);
        let specific = download_messages(None, None, Some(vec![accepted[0].msgs[0].uid.clone()])).unwrap();
        assert_eq!(specific.len(), 1);
        // No pending will return empty list
        let empty = download_messages(None, Some(vec!["MS-103".to_string()]), Some(vec![accepted[0].msgs[0].uid.clone()])).unwrap();
        assert_eq!(empty.len(), 1);
        // Agency returns a bad request response for invalid dids
        let invalid_did = "abc".to_string();
        let bad_req = download_messages(Some(vec![invalid_did]), None, None);
        assert_eq!(bad_req, Err(error::POST_MSG_FAILURE.code_num));
        teardown!("agency");
    }
}
