extern crate serde;
extern crate rmp_serde;
extern crate serde_json;

pub mod create_key;
pub mod invites;
pub mod validation;
pub mod get_message;
pub mod send_message;
pub mod update_profile;
pub mod proofs;
pub mod agent_utils;
pub mod update_connection;
pub mod update_message;

use std::u8;
use settings;
use utils::libindy::crypto;
use utils::libindy::wallet;
use utils::error;
use self::rmp_serde::encode;
use self::create_key::{CreateKeyMsgBuilder, CreateKeyMsg};
use self::update_connection::{ DeleteConnectionBuilder, DeleteConnection };
use self::invites::send::{SendInviteBuilder, SendInvite};
use self::invites::accept::{AcceptInviteBuilder, AcceptInvite};
use self::update_profile::{ UpdateProfileDataBuilder, UpdateProfileData };
use self::get_message::{ GetMessagesBuilder, GetMessages };
use self::send_message::{SendMessageBuilder, SendMessage };
use serde::Deserialize;
use self::rmp_serde::Deserializer;
use serde_json::Value;
use self::proofs::proof_request::{ProofRequestBuilder};

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
pub struct MsgInfo {
    pub name: String,
    pub ver: String,
    pub fmt: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
pub struct Payload {
    #[serde(rename = "@type")]
    pub msg_info: MsgInfo,
    #[serde(rename = "@msg")]
    pub msg: String,
}

//Todo: Update with all Messages. Have builder trait functionality
#[derive(Clone, Serialize, Debug, PartialEq, PartialOrd)]
pub enum MessageType {
    EmptyPayload{},
    CreateKeyMsg(CreateKeyMsg),
    SendInviteMsg(SendInvite),
    AcceptInvite(AcceptInvite),
    UpdateInfoMsg(UpdateProfileData),
    GetMessagesMsg(GetMessages),
    SendMessageMsg(SendMessage),
    DeleteConnectionMsg(DeleteConnection)
}

pub enum MessageResponseCode {
    MessageCreate,
    MessageSent,
    MessagePending,
    MessageAccepted,
    MessageRejected,
    MessageAnswered,
}

impl MessageResponseCode {
    pub fn as_string(&self) -> String {
        match *self {
            MessageResponseCode::MessageCreate => String::from("MS-101"),
            MessageResponseCode::MessageSent => String::from("MS-102"),
            MessageResponseCode::MessagePending => String::from("MS-103"),
            MessageResponseCode::MessageAccepted => String::from("MS-104"),
            MessageResponseCode::MessageRejected => String::from("MS-105"),
            MessageResponseCode::MessageAnswered => String::from("MS-106"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, PartialOrd)]
pub struct MsgType {
    name: String,
    ver: String,
}

#[derive(Serialize, Deserialize)]
pub struct MsgResponse {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    uid: String,
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

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
pub struct Bundled<T> {
    bundled: Vec<T>,
}

impl<T> Bundled<T> {
    pub fn create(bundled: T) -> Bundled<T> {
        let mut vec = Vec::new();
        vec.push(bundled);
        Bundled {
            bundled: vec,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, u32> where T: serde::Serialize {
        let result = match encode::to_vec_named(self) {
            Ok(x) => x,
            Err(x) => {
                error!("Could not convert bundle to messagepack: {}", x);
                return Err(error::INVALID_MSGPACK.code_num);
            },
        };

        Ok(result)
    }
}

pub fn try_i8_bundle(data: Vec<u8>) -> Result<Bundled<Vec<u8>>, u32> {
    let mut de = Deserializer::new(&data[..]);
    let bundle: Bundled<Vec<i8>> = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(_) => {
            warn!("could not deserialize bundle with i8, will try u8");
            return Err(error::INVALID_MSGPACK.code_num);
        },
    };

    let mut new_bundle: Bundled<Vec<u8>> = Bundled { bundled: Vec::new() };
    for i in bundle.bundled {
        let mut buf: Vec<u8> = Vec::new();
        for j in i {buf.push(j as u8);}
        new_bundle.bundled.push(buf);
    }
    Ok(new_bundle)
}

pub fn to_u8(bytes: &Vec<i8>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for i in bytes {buf.push(*i as u8);}
    buf.to_owned()
}

pub fn to_i8(bytes: &Vec<u8>) -> Vec<i8> {
    let mut buf: Vec<i8> = Vec::new();
    for i in bytes {buf.push(*i as i8);}
    buf.to_owned()
}

pub fn to_json(bytes: &Vec<u8>) -> Result<Value, u32> {
    let mut de = Deserializer::new(&bytes[..]);
    match Deserialize::deserialize(&mut de) {
        Ok(x) => Ok(x),
        Err(x) => Err(error::INVALID_JSON.code_num),
    }
}

pub fn bundle_from_u8(data: Vec<u8>) -> Result<Bundled<Vec<u8>>, u32> {
    let bundle = match try_i8_bundle(data.clone()) {
        Ok(x) => x,
        Err(x) => {
            let mut de = Deserializer::new(&data[..]);
            let bundle: Bundled<Vec<u8>> = match Deserialize::deserialize(&mut de) {
                Ok(x) => x,
                Err(x) => {
                    error!("could not deserialize bundle with i8 or u8: {}", x);
                    return Err(error::INVALID_MSGPACK.code_num);
                },
            };
            bundle
        },
    };

    Ok(bundle)
}

pub fn extract_json_payload(data: &Vec<u8>) -> Result<String, u32> {
    let mut de = Deserializer::new(&data[..]);
    let my_payload: Payload = match Deserialize::deserialize(&mut de) {
        Ok(x) => x,
        Err(x) => {
            error!("could not deserialize bundle with i8 or u8: {}", x);
            return Err(error::INVALID_MSGPACK.code_num);
            },
        };

    Ok(my_payload.msg.to_owned())
}

pub fn bundle_for_agency(message: Vec<u8>, did: &str) -> Result<Vec<u8>, u32> {
    let agency_vk = settings::get_config_value(settings::CONFIG_AGENCY_VERKEY)?;
    let agent_vk = settings::get_config_value(settings::CONFIG_REMOTE_TO_SDK_VERKEY)?;
    let my_vk = settings::get_config_value(settings::CONFIG_SDK_TO_REMOTE_VERKEY)?;

    trace!("pre encryption msg: {:?}", message);
    let msg = crypto::prep_msg(wallet::get_wallet_handle(), &my_vk, &agent_vk, &message[..])?;

    debug!("forwarding agency bundle to {}", did);
    let outer = Forward {
        msg_type: MsgType { name: "FWD".to_string(), ver: "1.0".to_string(), },
        fwd: did.to_owned(),
        msg,
    };
    let outer = encode::to_vec_named(&outer).or(Err(error::UNKNOWN_ERROR.code_num))?;

    trace!("forward bundle: {:?}", outer);
    let msg = Bundled::create(outer).encode()?;
    trace!("pre encryption bundle: {:?}", msg);
    crypto::prep_anonymous_msg(&agency_vk, &msg[..])
}

pub fn bundle_for_agent(message: Vec<u8>, pw_vk: &str, agent_did: &str, agent_vk: &str) -> Result<Vec<u8>, u32> {
    debug!("pre encryption msg: {:?}", message);
    let msg = crypto::prep_msg(wallet::get_wallet_handle(), &pw_vk, agent_vk, &message[..])?;

    /* forward to did */
    debug!("forwarding agent bundle to {}", agent_did);
    let inner = Forward {
        msg_type: MsgType { name: "FWD".to_string(), ver: "1.0".to_string(), },
        fwd: agent_did.to_string(),
        msg,
    };
    let inner = encode::to_vec_named(&inner).or(Err(error::UNKNOWN_ERROR.code_num))?;
    debug!("inner forward: {:?}", inner);

    let msg = Bundled::create(inner).encode()?;

    let to_did = settings::get_config_value(settings::CONFIG_REMOTE_TO_SDK_DID)?;
    bundle_for_agency(msg, &to_did)
}

pub fn unbundle_from_agency(message: Vec<u8>) -> Result<Vec<Vec<u8>>, u32> {

    let my_vk = settings::get_config_value(settings::CONFIG_SDK_TO_REMOTE_VERKEY)?;

    let (_, data) = crypto::parse_msg(&my_vk, &message[..])?;

    debug!("deserializing {:?}", data);
    let bundle:Bundled<Vec<u8>> = bundle_from_u8(data)?;

    Ok(bundle.bundled.clone())
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
pub struct Forward {
    #[serde(rename = "@type")]
    msg_type: MsgType,
    #[serde(rename = "@fwd")]
    fwd: String,
    #[serde(rename = "@msg")]
    msg: Vec<u8>,
}

pub trait GeneralMessageBuilder {
    type MsgBuilder;
    type Msg;

    //todo: deserialize_message

    fn new() -> Self::MsgBuilder;
    fn to(self, did: &str) -> Self::MsgBuilder;
    fn to_vk(self, vk: &str) -> Self::MsgBuilder;
    fn agent_did(self, did: &str) -> Self::MsgBuilder;
    fn agent_vk(self, vk: &str) -> Self::MsgBuilder;
    fn build(self) -> Result<Self::Msg, u32>;
}

pub trait GeneralMessage {
    type SendSecureResult;
    fn msgpack(&mut self) -> Result<Vec<u8>, u32>;
    fn send_secure(&mut self) -> Result<Self::SendSecureResult, u32>;
}

pub trait MsgUtils {
    fn optional_field<T>(&self, field: Option<Result<T, u32>>) -> Result<Option<T>, u32> {
        field.map_or(Ok(None), |rc| {
            rc.map(|x| Some(x))
        })
    }

    fn wrap_ok<T>(&self, field: T) -> Option<Result<T, u32>>  { Some(Ok(field)) }

    fn wrap_err<T>(&self, err: u32) -> Option<Result<T, u32>> { Some(Err(err))}
}

pub fn create_keys() -> CreateKeyMsgBuilder { CreateKeyMsgBuilder::new() }
pub fn send_invite() -> SendInviteBuilder { SendInviteBuilder::new() }
pub fn delete_connection() -> DeleteConnectionBuilder { DeleteConnectionBuilder::new() }
pub fn accept_invite() -> AcceptInviteBuilder { AcceptInviteBuilder::new() }
pub fn update_data() -> UpdateProfileDataBuilder { UpdateProfileDataBuilder::new() }
pub fn get_messages() -> GetMessagesBuilder { GetMessagesBuilder::new() }
pub fn send_message() -> SendMessageBuilder { SendMessageBuilder::new() }
pub fn proof_request() -> ProofRequestBuilder { ProofRequestBuilder::new() }

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_to_u8() {
        let vec: Vec<i8> = vec![-127, -89, 98, 117, 110, 100, 108, 101, 100, -111, -36, 5, -74];

        let buf = to_u8(&vec);
        println!("new bundle: {:?}", buf);
    }

    #[test]
    fn test_to_i8() {
        let vec: Vec<u8> = vec![129, 167, 98, 117, 110, 100, 108, 101, 100, 145, 220, 19, 13];
        let buf = to_i8(&vec);
        println!("new bundle: {:?}", buf);
    }
}
