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

#![allow(unused_variables)]

use crate::*;

#[test]
fn test_init_and_messaging() {
	
	// initialize testing environment
	let name = "alice";
	let comment = "\nhi\n\\{}[]{{}\"";
	let (bob_init_pk_curve, bob_init_sk_curve) = curve_keygen();
	let (bob_init_pk_curve_pfs_2, bob_init_sk_curve_pfs_2) = curve_keygen();
	let (bob_init_pk_kyber, bob_init_sk_kyber) = kyber_keygen();
	let (bob_init_pk_curve_for_salt, bob_init_sk_curve_for_salt) = curve_keygen();
	let (bob_init_pk_kyber_for_salt, bob_init_sk_kyber_for_salt) = kyber_keygen();
	let (bob_pk_sig, bob_sk_sig) = sign_keygen();
	let (alice_pk_sig, alice_sk_sig) = sign_keygen();
	
	// Alice sends an init request to Bob
	let mdc = mdc_gen();
	let ((alice_pk_kyber, alice_sk_kyber), (alice_pk_curve, alice_sk_curve), alice_new_pfs_key, recv_bob_pfs_key, pfs_salt, id, id_salt, _, mdc_seed, init_request_ciphertext) = gen_init_request(&bob_init_pk_kyber, &bob_init_pk_kyber_for_salt, &bob_init_pk_curve, &bob_init_pk_curve_pfs_2, &bob_init_pk_curve_for_salt, &alice_pk_sig, &alice_sk_sig, name, comment, &mdc).unwrap();
	
	// Bob's client parses the init request
	let (recv_id, recv_id_salt, recv_mdc, recv_alice_pk_kyber, recv_alice_pk_sig, bob_pfs_key, recv_alice_new_pfs_key, recv_pfs_salt, recv_name, recv_comment, recv_mdc_seed) = parse_init_request(&init_request_ciphertext, &bob_init_sk_kyber, &bob_init_sk_curve, &bob_init_sk_curve_pfs_2, &bob_init_sk_kyber_for_salt, &bob_init_sk_curve_for_salt).unwrap();
	
	// check the received init request
	assert_eq!(recv_id, id);
	assert_eq!(recv_id_salt, id_salt);
	assert_eq!(recv_mdc, mdc);
	assert_eq!(recv_alice_pk_kyber, alice_pk_kyber);
	assert_eq!(recv_alice_pk_sig, alice_pk_sig);
	assert_eq!(recv_alice_new_pfs_key, alice_new_pfs_key);
	assert_eq!(recv_bob_pfs_key, bob_pfs_key);
	assert_eq!(recv_pfs_salt, pfs_salt);
	assert_eq!(recv_name, name);
	assert_eq!(recv_comment, comment);
	assert_eq!(recv_mdc_seed, mdc_seed);
	
	// Bob accepts the init request
	let (bob_new_pfs_key_2, (bob_pk_kyber, bob_sk_kyber), mdc_2, init_accept_ciphertext) = accept_init_request(&bob_pk_sig, &bob_sk_sig, &recv_alice_pk_kyber, &bob_pfs_key, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Check security number derivation
	let security_number = derive_security_number(&alice_pk_kyber, &bob_pk_kyber).unwrap();
	assert_eq!(security_number.len(), 64);
	println!("Security number: {}", security_number);
	
	// Alice happily receives the accept message
	let (recv_bob_pk_kyber, recv_bob_pk_sig, recv_bob_new_pfs_key_2, mdc_3) = parse_init_response(&init_accept_ciphertext, &alice_sk_kyber, None, &recv_bob_pfs_key, &pfs_salt).unwrap();
	
	// check the received values
	assert_eq!(recv_bob_pk_kyber, bob_pk_kyber);
	assert_eq!(recv_bob_pk_sig, bob_pk_sig);
	assert_eq!(bob_new_pfs_key_2, recv_bob_new_pfs_key_2);
	assert_eq!(mdc_2, mdc_3);
	
	// now we can send some messages!
	// Bob sends the first message
	let (bob_new_pfs_key_3, mdc_4, bob_msg_ciphertext_1) = send_msg((content_type::TEXT, Some("Hi Alice"), None), &alice_pk_kyber, Some(&bob_sk_sig), &bob_new_pfs_key_2, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Alice receives it
	let ((recv_content_type, recv_text, recv_bytes), recv_bob_new_pfs_key_3, mdc_5) = parse_msg(&bob_msg_ciphertext_1, &alice_sk_kyber, Some(&bob_pk_sig), &recv_bob_new_pfs_key_2, &pfs_salt).unwrap();
	
	// check what was received
	assert_eq!(recv_content_type, content_type::TEXT);
	assert_eq!(recv_text, Some("Hi Alice".to_string()));
	assert_eq!(recv_bytes, None);
	assert_eq!(recv_bob_new_pfs_key_3, bob_new_pfs_key_3);
	assert_eq!(mdc_4, mdc_5);
	
	// Alice sends two messages
	let (alice_new_pfs_key_2, mdc_6, alice_msg_ciphertext_1) = send_msg((content_type::TEXT, Some("Hi Bob"), None), &bob_pk_kyber, Some(&alice_sk_sig), &alice_new_pfs_key, &pfs_salt, &id, &mdc_seed).unwrap();
	let (alice_new_pfs_key_3, mdc_7, alice_msg_ciphertext_2) = send_msg((content_type::TEXT, Some("How are you?"), None), &bob_pk_kyber, Some(&alice_sk_sig), &alice_new_pfs_key_2, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Bob receives both messages
	let ((recv_content_type_1, recv_text_1, recv_bytes_1), recv_alice_new_pfs_key_2, mdc_8) = parse_msg(&alice_msg_ciphertext_1, &bob_sk_kyber, Some(&alice_pk_sig), &recv_alice_new_pfs_key, &pfs_salt).unwrap();
	let ((recv_content_type_2, recv_text_2, recv_bytes_2), recv_alice_new_pfs_key_3, mdc_9) = parse_msg(&alice_msg_ciphertext_2, &bob_sk_kyber, Some(&alice_pk_sig), &recv_alice_new_pfs_key_2, &pfs_salt).unwrap();
	
	// check what was received
	assert!(recv_content_type_1 == recv_content_type_2 && recv_content_type_1 == content_type::TEXT);
	assert_eq!(recv_text_1, Some("Hi Bob".to_string()));
	assert_eq!(recv_text_2, Some("How are you?".to_string()));
	assert!(recv_bytes_1.is_none() && recv_bytes_2.is_none());
	assert_eq!(recv_alice_new_pfs_key_2, alice_new_pfs_key_2);
	assert_eq!(recv_alice_new_pfs_key_3, alice_new_pfs_key_3);
	assert_ne!(alice_new_pfs_key_2, alice_new_pfs_key_3);
	assert_ne!(bob_new_pfs_key_2, bob_new_pfs_key_3);
	assert_eq!(mdc_6, mdc_8);
	assert_eq!(mdc_7, mdc_9);
	
	// Bob sends a message
	let (bob_new_pfs_key_4, mdc_10, bob_msg_ciphertext_2) = send_msg((content_type::TEXT, Some("I'm very happy because the test just passed!"), None), &alice_pk_kyber, Some(&bob_sk_sig), &bob_new_pfs_key_3, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Alice receives it
	let ((recv_content_type, recv_text, recv_bytes), recv_bob_new_pfs_key_4, mdc_11) = parse_msg(&bob_msg_ciphertext_2, &alice_sk_kyber, Some(&bob_pk_sig), &recv_bob_new_pfs_key_3, &pfs_salt).unwrap();
	
	// check what was received
	assert_eq!(recv_content_type, content_type::TEXT);
	assert_eq!(recv_text, Some("I'm very happy because the test just passed!".to_string()));
	assert!(recv_bytes.is_none());
	assert_eq!(recv_bob_new_pfs_key_4, bob_new_pfs_key_4);
	assert_eq!(mdc_10, mdc_11);
	
	// Alice sends a voice message
	let (alice_new_pfs_key_3, mdc_12, alice_msg_ciphertext_3) = send_msg((content_type::VOICE, None, Some(&vec![1,3,5,7,9,42])), &bob_pk_kyber, Some(&alice_sk_sig), &alice_new_pfs_key_2, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Bob receives it
	let ((recv_content_type, recv_text, recv_bytes), recv_alice_new_pfs_key_3, mdc_13) = parse_msg(&alice_msg_ciphertext_3, &bob_sk_kyber, Some(&alice_pk_sig), &recv_alice_new_pfs_key_2, &pfs_salt).unwrap();
	
	assert_eq!(recv_content_type, content_type::VOICE);
	assert!(recv_text.is_none());
	assert_eq!(recv_bytes, Some(vec![1,3,5,7,9,42]));
	assert_eq!(recv_alice_new_pfs_key_3, alice_new_pfs_key_3);
	assert_eq!(mdc_12, mdc_13);
	assert_ne!(alice_new_pfs_key_2, alice_new_pfs_key_3);
	
	// Bob sends a picture
	let (bob_new_pfs_key_5, mdc_14, bob_msg_ciphertext_3) = send_msg((content_type::PICTURE, Some("Here is a photo for you!"), Some(&vec![42,42,42,42,7,6,5,4,3,2,1])), &alice_pk_kyber, Some(&bob_sk_sig), &bob_new_pfs_key_4, &pfs_salt, &id, &mdc_seed).unwrap();
	
	// Alice receives it
	let ((recv_content_type, recv_text, recv_bytes), recv_bob_new_pfs_key_5, mdc_15) = parse_msg(&bob_msg_ciphertext_3, &alice_sk_kyber, Some(&bob_pk_sig), &recv_bob_new_pfs_key_4, &pfs_salt).unwrap();
	
	assert_eq!(recv_content_type, content_type::PICTURE);
	assert_eq!(recv_text, Some("Here is a photo for you!".to_string()));
	assert_eq!(recv_bytes, Some(vec![42,42,42,42,7,6,5,4,3,2,1]));
	assert_eq!(recv_bob_new_pfs_key_5, bob_new_pfs_key_5);
	assert_eq!(mdc_14, mdc_15);
	assert_ne!(bob_new_pfs_key_4, bob_new_pfs_key_5);
	
	// Alice sends a large media file (using LinkedMediaMessage)
	let link = "https://contentserver.dawn-privacy.org/f/42";
	let key = "42424242";
	let comment = "This is a test file!\nThe comment can use multiple lines just like a normal message!\nPretty neat, right? :)";
	let msg_string = link.to_string() + "\n" + key + "\n" + comment;
	let (alice_new_pfs_key_4, mdc_16, alice_msg_ciphertext_4) = send_msg((content_type::LINKED_MEDIA, Some(&msg_string), Some(&vec![42])), &bob_pk_kyber, Some(&alice_sk_sig), &alice_new_pfs_key_3, &pfs_salt, &id, &mdc).unwrap();
	
	// Bob receives it
	let ((recv_content_type, recv_text, recv_bytes), recv_alice_new_pfs_key_4, mdc_17) = parse_msg(&alice_msg_ciphertext_4, &bob_sk_kyber, Some(&alice_pk_sig), &recv_alice_new_pfs_key_3, &pfs_salt).unwrap();
	
	assert_eq!(recv_content_type, content_type::LINKED_MEDIA);
	assert_eq!(recv_text, Some(link.to_string() + "\n" + key + "\n" + comment));
	assert_eq!(recv_bytes, Some(vec![42]));
	assert_eq!(recv_alice_new_pfs_key_4, alice_new_pfs_key_4);
	assert_eq!(mdc_16, mdc_17);
	assert_ne!(alice_new_pfs_key_4, alice_new_pfs_key_3);
}

#[test]
fn test_handle_parsing() {
	let init_pk_kyber = vec![255,0,255,1,2,3,4,5];
	let init_pk_curve = vec![5,5,6];
	let init_pk_curve_pfs_2 = vec![42,5,5,5];
	let init_pk_kyber_for_salt = vec![42,42,0,0,0];
	let init_pk_curve_for_salt = vec![0,0,3,0];
	let name = "Test 42";
	let mdc = mdc_gen();
	let handle = gen_handle(&init_pk_kyber, &init_pk_curve, &init_pk_curve_pfs_2, &init_pk_kyber_for_salt, &init_pk_curve_for_salt, name, &mdc);
	let (parsed_init_pk_kyber, parsed_init_pk_curve, parsed_init_pk_curve_pfs_2, parsed_init_pk_kyber_for_salt, parsed_init_pk_curve_for_salt, parsed_name, parsed_mdc) = parse_handle(handle).unwrap();
	assert_eq!(init_pk_kyber, parsed_init_pk_kyber);
	assert_eq!(init_pk_curve, parsed_init_pk_curve);
	assert_eq!(init_pk_curve_pfs_2, parsed_init_pk_curve_pfs_2);
	assert_eq!(init_pk_kyber_for_salt, parsed_init_pk_kyber_for_salt);
	assert_eq!(init_pk_curve_for_salt, parsed_init_pk_curve_for_salt);
	assert_eq!(name, parsed_name);
	assert_eq!(mdc, parsed_mdc);
}

#[test]
fn test_gen_init_request() {
	assert!(gen_init_request(&vec![], &vec![], &vec![], &vec![], &vec![], &vec![], &vec![], "", "", "").is_err());
	let name = "alice";
	let comment = "\nhi\n\\{}[]{{}\"";
	let mdc = mdc_gen();
	let (bob_init_pk_curve, bob_init_sk_curve) = curve_keygen();
	let (bob_init_pk_kyber, bob_init_sk_kyber) = kyber_keygen();
	let (alice_pk_sig, alice_sk_sig) = sign_keygen();
	assert!(gen_init_request(&bob_init_pk_kyber, &bob_init_pk_kyber, &bob_init_pk_curve, &bob_init_pk_curve, &bob_init_pk_curve, &alice_pk_sig, &alice_sk_sig, "", comment, &mdc).is_err());
}
