/*	Copyright (c) 2022, 2023 Laurenz Werner
	
	This file is part of Dawn.
	
	Dawn is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	Dawn is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.
*/

use dawn_crypto::*;
use serde::{Serialize, Deserialize};
use hex::{encode, decode};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use crate::Message::*;

// re-exports that can be directly used by the Dawn client
pub use dawn_crypto::{init as init_crypto, sign_keygen, id_gen, get_temp_id, get_next_id, derive_security_number, sym_key_gen};

mod content_type;

#[cfg(test)]
mod tests;

// Error return macro
macro_rules! error{
	($a:expr) => {
		return Err($a.to_string())
	}
}

#[derive(Serialize, Deserialize, Debug)]
enum Message {
	InitRequest(InitRequest),
	InitAccept(InitAccept),
	Text(TextMessage),
	Internal(InternalMessage),
	Voice(VoiceMessage),
	Picture(PictureMessage),
	LinkedMedia(LinkedMediaMessage)
}

#[derive(Serialize, Deserialize, Debug)]
struct InitRequest {
	id: String,
	mdc: String,
	kyber: String,
	sign: String,
	name: String,
	comment: String
}

#[derive(Serialize, Deserialize, Debug)]
struct InitAccept {
	kyber: String,
	sign: String,
	mdc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TextMessage {
	text: String,
	mdc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct InternalMessage {
	event: u8,
	event_data: String,
	mdc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VoiceMessage {
	voice: String,
	mdc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PictureMessage {
	picture: String,
	description: String,
	mdc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinkedMediaMessage {
	media_type: u8,
	media_link: String,
	media_key: String,
	description: String,
	mdc: String
}

// generate an init request using init id, init keys and own signature key
// returns: (own kyber public key, own kyber secret key), (own curve public key, own curve secret key), pfs key, id, message detail code, encrypted message
pub fn gen_init_request(
	remote_pubkey_kyber: &[u8],
	remote_pubkey_curve: &[u8],
	own_pubkey_sig: &[u8],
	own_seckey_sig: &[u8],
	name: &str,
	comment: &str
) -> Result<
	(
		(Vec<u8>, Vec<u8>), // own kyber keypair
		(Vec<u8>, Vec<u8>), // own curve keypair
		Vec<u8>, // pfs key
		String, // id
		String, // message detail code
		Vec<u8> // encrypted message
	), String> {
	
	let ((own_pubkey_kyber, own_seckey_kyber), (own_pubkey_curve, own_seckey_curve), id) = init();
	let pfs_key = match get_curve_secret(&own_seckey_curve, &remote_pubkey_curve) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	let mdc = mdc_gen();
	
	// generate message
	let message_data = Message::InitRequest( InitRequest {
		id: id.to_string(),
		mdc: mdc.to_string(),
		kyber: encode(own_pubkey_kyber.clone()),
		sign: encode(own_pubkey_sig),
		name: name.to_string(),
		comment: comment.to_string()
	} );
	let message = match serde_json::to_string(&message_data) {
		Ok(res) => res,
		Err(_) => error!("json serialization failed")
	};
	
	// encrypt using derived pfs key
	let (mut msg_ciphertext, new_pfs_key) = match encrypt_msg(remote_pubkey_kyber, own_seckey_sig, &pfs_key, &message) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	// put the curve public key in front as it is needed to derive the pfs key
	let mut ciphertext = own_pubkey_curve.clone();
	ciphertext.append(&mut msg_ciphertext);
	
	Ok(((own_pubkey_kyber, own_seckey_kyber), (own_pubkey_curve, own_seckey_curve), new_pfs_key, id, mdc, ciphertext))
}

// parse an init request
// returns id, mdc, keys, name and comment
pub fn parse_init_request(request_body: &[u8], own_seckey_kyber: &[u8], own_seckey_curve: &[u8]) -> Result<(String, String, Vec<u8>, Vec<u8>, Vec<u8>, String, String), String> {
	// check length
	if request_body.len() <= 32 { error!("request was too short!"); }
	
	let (remote_pubkey_curve, ciphertext) = request_body.split_at(32);
	let pfs_key = match get_curve_secret(own_seckey_curve, remote_pubkey_curve) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	// decrypt
	let (msg_content, new_pfs_key) = match decrypt_msg(own_seckey_kyber, None, &pfs_key, ciphertext) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	// parse
	let message = match serde_json::from_str::<Message>(&msg_content) {
		Ok(res) => res,
		Err(_) => error!("json parsing failed")
	};
	
	let init_request = match message {
		InitRequest(req) => req,
		_ => error!("content did not match init request type")
	};
	
	let remote_pubkey_kyber = match decode(&init_request.kyber) {
		Ok(res) => res,
		Err(_) => error!("remote kyber pubkey invalid")
	};
	let remote_pubkey_sig = match decode(&init_request.sign) {
		Ok(res) => res,
		Err(_) => error!("remote signature pubkey invalid")
	};
	
	Ok((init_request.id, init_request.mdc, remote_pubkey_kyber, remote_pubkey_sig, new_pfs_key, init_request.name, init_request.comment))
}

// accept init request
// returns the new PFS key, own kyber keypair, message detail code and ciphertext
pub fn accept_init_request(own_pubkey_sig: &[u8], own_seckey_sig: &[u8], remote_pubkey_kyber: &[u8], pfs_key: &[u8]) -> Result<(Vec<u8>, (Vec<u8>, Vec<u8>), String, Vec<u8>), String> {
	let mdc = mdc_gen();
	let (own_pubkey_kyber, own_seckey_kyber) = kyber_keygen();
	
	let message_data = Message::InitAccept( InitAccept {
		kyber: encode(&own_pubkey_kyber),
		sign: encode(&own_pubkey_sig),
		mdc: mdc.clone(),
	} );
	let message = match serde_json::to_string(&message_data) {
		Ok(res) => res,
		Err(_) => error!("json serialization failed")
	};
	
	// encrypt message
	let (msg_ciphertext, new_pfs_key) = match encrypt_msg(remote_pubkey_kyber, own_seckey_sig, pfs_key, &message) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	Ok((new_pfs_key, (own_pubkey_kyber, own_seckey_kyber), mdc, msg_ciphertext))
}

// parse init response message (expected to be the first message on a new ID after an init request was sent)
// As of now, only accept messages are sent. If the user rejects the request, no message is sent. Therefore, we only try to parse init accept messages.
// returns remote kyber and signature pubkeys, the new PFS key and message detail code
pub fn parse_init_response(msg_ciphertext: &[u8], own_seckey_kyber: &[u8], pfs_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, String), String> {
	// decrypt
	let (msg_content, new_pfs_key) = match decrypt_msg(own_seckey_kyber, None, pfs_key, msg_ciphertext) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	// parse
	let message = match serde_json::from_str::<Message>(&msg_content) {
		Ok(res) => res,
		Err(_) => error!("json parsing failed")
	};
	
	let init_accept = match message {
		InitAccept(resp) => resp,
		_ => error!("content did not match init accept type")
	};
	
	let remote_pubkey_kyber = match decode(&init_accept.kyber) {
		Ok(res) => res,
		Err(_) => error!("remote kyber pubkey invalid")
	};
	let remote_pubkey_sig = match decode(&init_accept.sign) {
		Ok(res) => res,
		Err(_) => error!("remote signature pubkey invalid")
	};
	
	Ok((remote_pubkey_kyber, remote_pubkey_sig, new_pfs_key, init_accept.mdc))
}

// parse a received message
// returns content type, content (can be a string, a Vec or both depending on the message type), new PFS key and message detail code
pub fn parse_msg(msg_ciphertext: &[u8], own_seckey_kyber: &[u8], remote_pubkey_sig: Option<&[u8]>, pfs_key: &[u8]) -> Result<((u8, Option<String>, Option<Vec<u8>>), Vec<u8>, String), String> {
	// decrypt
	let (msg_content, new_pfs_key) = match decrypt_msg(own_seckey_kyber, remote_pubkey_sig, pfs_key, msg_ciphertext) {
		Ok(res) => res,
		Err(_) => error!("decryption failed")
	};
	
	// parse
	let message = match serde_json::from_str::<Message>(&msg_content) {
		Ok(res) => res,
		Err(_) => error!("json parsing failed")
	};
	
	let (content, mdc) = match message {
		Text(msg) => ((content_type::TEXT, Some(msg.text), None::<Vec<u8>>), msg.mdc),
		Internal(msg) => ((content_type::INTERNAL, Some(msg.event_data), None), msg.mdc),
		Voice(msg) => {
			let msg_bytes = BASE64.decode(&msg.voice);
			if msg_bytes.is_err() { error!("voice message data invalid"); }
			((content_type::VOICE, None::<String>, Some(msg_bytes.unwrap())), msg.mdc)
		},
		Picture(msg) => {
			let msg_bytes = BASE64.decode(&msg.picture);
			if msg_bytes.is_err() { error!("picture data invalid"); }
			((content_type::PICTURE, Some(msg.description), Some(msg_bytes.unwrap())), msg.mdc)
		},
		LinkedMedia(msg) => ((content_type::LINKED_MEDIA, Some(msg.media_link + "\n" + &msg.media_key + "\n" + &msg.description), Some(vec![msg.media_type])), msg.mdc),
		_ => error!("message type not known or unexpected init message")
	};
	
	Ok((content, new_pfs_key, mdc))
}

// send a message
// returns new PFS key, message detail code and ciphertext
pub fn send_msg((msg_type, msg_text, msg_data): (u8, Option<&str>, Option<&[u8]>), remote_pubkey_kyber: &[u8], own_seckey_sig: &[u8], pfs_key: &[u8]) -> Result<(Vec<u8>, String, Vec<u8>), String> {
	// create message
	let mdc = mdc_gen();
	let message_data: Message = match msg_type {
		content_type::TEXT => { 
			if msg_text.is_none() { error!("no text was provided"); }
			Message::Text( TextMessage {
				text: String::from(msg_text.unwrap()),
				mdc: mdc.clone()
			} )
		},
		content_type::INTERNAL => {
			if msg_text.is_none() { error!("no event code was provided"); }
			let event_id = msg_text.unwrap().parse::<u8>();
			if event_id.is_err() { error!("invalid event code"); }
			if msg_data.is_none() { error!("missing event data"); }
			Message::Internal( InternalMessage {
				event: event_id.unwrap(),
				event_data: BASE64.encode(&msg_data.unwrap()),
				mdc: mdc.clone()
			} )
		},
		content_type::VOICE => {
			if msg_data.is_none() { error!("no voice data was provided"); }
			Message::Voice( VoiceMessage {
				voice: BASE64.encode(&msg_data.unwrap()),
				mdc: mdc.clone()
			} )
		},
		content_type::PICTURE => {
			if msg_data.is_none() { error!("no picture data was provided"); }
			let description = match msg_text {
				Some(text) => text,
				None => ""
			};
			Message::Picture( PictureMessage {
				picture: BASE64.encode(&msg_data.unwrap()),
				description: description.to_string(),
				mdc: mdc.clone()
			} )
		},
		content_type::LINKED_MEDIA => {
			// This data currently has to be provided in a special format:
			// msg_data is one byte that indicates the media type
			// msg_text contains the link to the media file in the first line and the encoded symmetric key in the second line. All following lines are interpreted as the description.
			if msg_data.is_none() { error!("no voice data was provided"); }
			let msg_data = msg_data.unwrap();
			if msg_data.len() != 1 { error!(&format!("expected 1 byte to identify media type, got {} bytes", msg_data.len())); }
			if msg_text.is_none() { error!("no link was provided"); }
			let mut text_data = msg_text.unwrap().lines();
			let media_link = text_data.next().unwrap();
			let media_key = match text_data.next() {
				Some(key) => key,
				None => { error!("no media key was provided"); }
			};
			let mut description = String::new();
			for line in text_data {
				description += line;
				description += "\n";
			}
			description.pop();
			Message::LinkedMedia( LinkedMediaMessage {
				media_type: msg_data[0],
				media_link: media_link.to_string(),
				media_key: media_key.to_string(),
				description: description,
				mdc: mdc.clone()
			} )
		},
		_ => error!("requested content type not implemented")
	};
	
	let message = match serde_json::to_string(&message_data) {
		Ok(res) => res,
		Err(_) => error!("json serialization failed")
	};
	
	// encrypt message
	let (msg_ciphertext, new_pfs_key) = match encrypt_msg(remote_pubkey_kyber, own_seckey_sig, pfs_key, &message) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	Ok((new_pfs_key, mdc, msg_ciphertext))
}

// This encrypts a file using a random key and returns the ciphertext and key
pub fn encrypt_file(file: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
	let key = sym_key_gen();
	let ciphertext = match encrypt_data(file, &key) {
		Ok(res) => res,
		Err(err) => { error!(&format!("file encryption failed: {}", err)); }
	};
	Ok((ciphertext, key))
}

// This decrypts a file using the symmetric key and returns the cleartext file
pub fn decrypt_file(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
	let file = match decrypt_data(ciphertext, key) {
		Ok(res) => res,
		Err(err) => { error!(&format!("file decryption failed: {}", err)); }
	};
	Ok(file)
}


// this generates a handle
pub fn gen_handle(init_pubkey_kyber: Vec<u8>, init_pubkey_curve: Vec<u8>, name: &str) -> Vec<u8> {
	let init_pubkey_kyber_string = encode(&init_pubkey_kyber);
	let init_pubkey_curve_string = encode(&init_pubkey_curve);
	let handle_content = format!("{}\n{}\n{}", init_pubkey_kyber_string, init_pubkey_curve_string, name);
	handle_content.as_bytes().to_vec()
}

// this parses a handle
pub fn parse_handle(handle_content: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, String), String> {
	let handle_string = match String::from_utf8(handle_content) {
		Ok(res) => res,
		Err(_) => error!("handle content is not valid UTF-8!")
	};
	let mut information = handle_string.split("\n");
	
	let init_pubkey_kyber = match information.next() {
		Some(res) => match decode(res) {
			Ok(bytes) => bytes.to_vec(),
			Err(_) => error!("handle format invalid!")
		},
		None => error!("handle format invalid!")
	};
	let init_pubkey_curve = match information.next() {
		Some(res) => match decode(res) {
			Ok(bytes) => bytes.to_vec(),
			Err(_) => error!("handle format invalid!")
		},
		None => error!("handle format invalid!")
	};
	let name = match information.next() {
		Some(res) => res.to_string(),
		None => error!("handle format invalid!")
	};
	Ok((init_pubkey_kyber, init_pubkey_curve, name))
}
