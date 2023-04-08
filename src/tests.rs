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

use crate::*;

#[test]
fn test_init_and_messaging() {
	
	// initialize testing environment
	let name = "alice";
	let comment = "\nhi\n\\{}[]{{}\"";
	let (bob_init_pk_curve, bob_init_sk_curve) = curve_keygen();
	let (bob_init_pk_kyber, bob_init_sk_kyber) = kyber_keygen();
	let (bob_pk_sig, bob_sk_sig) = sign_keygen();
	let (alice_pk_sig, alice_sk_sig) = sign_keygen();
	
	// Alice sends an init request to Bob
	let ((alice_pk_kyber, alice_sk_kyber), (alice_pk_curve, alice_sk_curve), new_pfs_key, id, mdc, init_request_ciphertext) = gen_init_request(bob_init_pk_kyber, bob_init_pk_curve, alice_pk_sig.clone(), alice_sk_sig, name, comment).unwrap();
	
	// Bob's client parses the init request
	let (recv_id, recv_mdc, recv_alice_pk_kyber, recv_alice_pk_sig, recv_new_pfs_key, recv_name, recv_comment) = parse_init_request(&init_request_ciphertext, bob_init_sk_kyber, bob_init_sk_curve).unwrap();
	
	// check the received init request
	assert_eq!(recv_id, id);
	assert_eq!(recv_mdc, mdc);
	assert_eq!(recv_alice_pk_kyber, alice_pk_kyber);
	assert_eq!(recv_alice_pk_sig, alice_pk_sig);
	assert_eq!(recv_new_pfs_key, new_pfs_key);
	assert_eq!(recv_name, name);
	assert_eq!(recv_comment, comment);
	
	// Bob accepts the init request
	let (bob_new_pfs_key_2, (bob_pk_kyber, bob_sk_kyber), mdc_2, init_accept_ciphertext) = accept_init_request(bob_pk_sig.clone(), bob_sk_sig, recv_alice_pk_kyber, new_pfs_key.clone()).unwrap();
	
	// Alice happily receives the accept message
	let (recv_bob_pk_kyber, recv_bob_pk_sig, alice_new_pfs_key_2, mdc_3) = parse_init_response(&init_accept_ciphertext, alice_sk_kyber, new_pfs_key).unwrap();
	
	// check the received values
	assert_eq!(recv_bob_pk_kyber, bob_pk_kyber);
	assert_eq!(recv_bob_pk_sig, bob_pk_sig);
	assert_eq!(alice_new_pfs_key_2, bob_new_pfs_key_2);
	assert_eq!(mdc_2, mdc_3);
	
	// now we can send some messages!
	
}

#[test]
fn test_handle_parsing() {
	let init_pk_kyber = vec![255,0,255,1,2,3,4,5];
	let init_pk_curve = vec![5,5,6];
	let name = "Test 42";
	let handle = gen_handle(init_pk_kyber.clone(), init_pk_curve.clone(), name);
	let (parsed_init_pk_kyber, parsed_init_pk_curve, parsed_name) = parse_handle(handle).unwrap();
	assert_eq!(init_pk_kyber, parsed_init_pk_kyber);
	assert_eq!(init_pk_curve, parsed_init_pk_curve);
	assert_eq!(name, parsed_name);
}
