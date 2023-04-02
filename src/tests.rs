use crate::*;

#[test]
fn test_init_and_messaging() {
	// Alice sends an init request to bob
	let name = "alice";
	let comment = "\nhi\n\\{}[]{{}\"";
	let (bob_init_pk_curve, bob_init_sk_curve) = curve_keygen();
	let (bob_init_pk_kyber, bob_init_sk_kyber) = kyber_keygen();
	let (bob_pk_sig, bob_sk_sig) = sign_keygen();
	let (alice_pk_sig, alice_sk_sig) = sign_keygen();
	let ((alice_pk_kyber, alice_sk_kyber), (alice_pk_curve, alice_sk_curve), new_pfs_key, id, mdc, init_request_ciphertext) = gen_init_request(bob_init_pk_kyber, bob_init_pk_curve, alice_pk_sig.clone(), alice_sk_sig, name, comment).unwrap();
	let (recv_id, recv_mdc, recv_alice_pk_kyber, recv_alice_pk_sig, recv_new_pfs_key, recv_name, recv_comment) = parse_init_request(&init_request_ciphertext, bob_init_sk_kyber, bob_init_sk_curve).unwrap();
	assert_eq!(recv_id, id);
	assert_eq!(recv_mdc, mdc);
	assert_eq!(recv_alice_pk_kyber, alice_pk_kyber);
	assert_eq!(recv_alice_pk_sig, alice_pk_sig);
	assert_eq!(recv_new_pfs_key, new_pfs_key);
	assert_eq!(recv_name, name);
	assert_eq!(recv_comment, comment);
	
	// Bob accepts the init request
	let (new_pfs_key_2, (bob_pk_kyber, bob_sk_kyber), mdc_2, init_accept_ciphertext) = accept_init_request(bob_pk_sig, bob_sk_sig, recv_alice_pk_kyber, new_pfs_key).unwrap();
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
