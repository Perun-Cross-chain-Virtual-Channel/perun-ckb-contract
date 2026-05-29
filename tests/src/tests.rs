use crate::perun::mutators::*;
use crate::perun::random;
use crate::perun::virtual_channel::*;

use super::*;
use alloy_sol_types::SolValue;
use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use perun;
use perun::{test, virtual_channel};
use perun_common::channels::{
    is_coordinated_eligible, is_multi_ledger_state, verify_coordinator_sig,
};
use perun_common::perun_types::{
    Allocation, AnyBalances, AnyBalancesUnion, Balances, Bool, CKByteDistribution,
    ChannelParameters, ChannelState, Coordinator, ETHAsset, ETHBalances, ETHDistribution,
    EthAddress, LockedBalances, Participant, SEC1EncodedPubKey, SubAlloc,
};
use perun_common::sig::{ethereum_message_hash, verify_signature};
use perun_common::sol::{convert_ckb_state, convert_params, eth_address_from_sec1_pubkey};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

const MAX_CYCLES: u64 = 100 * 10_000_000;
const CHALLENGE_DURATION_MS: u64 = 10 * 1000;

// Include your tests here
// See https://github.com/xxuejie/ckb-native-build-sample/blob/main/tests/src/tests.rs for more examples

#[test]
fn test_signature() {
    // This tests the interoperability between the on-chain signature verification
    // and the key generation & signing in the perun-ckb-backend's wallet.

    // For determinism with the new `convert_ckb_state`, create a fixed
    // signing key, derive its compressed SEC1 pubkey, and sign the
    // computed message hash below so the test remains stable.
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::from_bytes((&[0x11u8; 32]).into()).expect("invalid sk");
    let verifying_key = sk.verifying_key();
    let pk_point = verifying_key.to_encoded_point(true);
    let pk_bytes_vec = pk_point.as_bytes().to_vec();
    let pubkey_bytes: [Byte; 33] = pk_bytes_vec
        .iter()
        .map(|b| Byte::from(*b))
        .collect::<Vec<Byte>>()
        .try_into()
        .unwrap();
    SEC1EncodedPubKey::new_builder().set(pubkey_bytes).build();

    let balances_array: [Uint64; 2] = [10u64.pack(), 11u64.pack()];
    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::CKByteDistribution(
                            CKByteDistribution::new_builder()
                                .set(balances_array)
                                .build(),
                        ))
                        .build(),
                )
                .build(),
        )
        .locked(
            LockedBalances::new_builder()
                .push(SubAlloc::new_builder().build())
                .build(),
        )
        .build();
    let channel_state = ChannelState::new_builder()
        .channel_id(Byte32::zero())
        .balances(balances)
        .is_final(Bool::from_bool(true))
        .version(10u64.pack())
        .build();
    let state_eth = convert_ckb_state(&channel_state);
    println!("State: {:?}", state_eth);
    let state_abi_encoded = state_eth.abi_encode();
    println!("Encoded: {:?}", state_abi_encoded);
    let msg_hash = ethereum_message_hash(&state_abi_encoded);
    println!("Hash: {:?}", msg_hash);
    let sig: k256::ecdsa::Signature = sk.sign_prehash(&msg_hash).expect("sign failed");
    let sig_bytes: Bytes = sig.to_der().as_bytes().to_vec().into();
    verify_signature(&msg_hash, &sig_bytes, pk_point.as_bytes()).expect("valid signature");
}

fn u128_le_as_uint128(v: u128) -> Uint128 {
    let le = v.to_le_bytes();
    // Uint128 expects exactly 16 bytes
    Uint128::new_unchecked(molecule::bytes::Bytes::from(le.to_vec()))
}

fn eth_address_from_hex(s: &str) -> EthAddress {
    let s = s.trim_start_matches("0x");
    let raw = hex::decode(s).expect("valid hex address");
    assert_eq!(raw.len(), 20);
    let arr20: [Byte; 20] = raw
        .into_iter()
        .map(|b| Byte::from(b))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    EthAddress::new_builder().set(arr20).build()
}
#[test]
fn test_cross_signature() {
    // This tests the interoperability between the on-chain signature verification
    // and the key generation & signing in the perun-ckb-backend's wallet.

    let channel_id_bytes: [u8; 32] = [
        44, 200, 243, 93, 27, 28, 68, 193, 103, 206, 252, 229, 221, 0, 109, 14, 208, 193, 32, 231,
        123, 54, 49, 227, 99, 145, 72, 1, 70, 113, 99, 168,
    ];

    // Version
    let version: u64 = 1;

    // CKBytes balances (Uint64 each)
    let ck_a: u64 = 8_000_000_000;
    let ck_b: u64 = 18_000_000_000;

    // One ETH asset:
    let eth_chain_id: u128 = 1337; // will be taken LE as Uint128
    let eth_addr_hex = "4E1D65a1E558029058903528140438802a6B5dfC";
    let eth_a: u128 = 1_000_000_000_000_000_000u128; // 1e18
    let eth_b: u128 = 0;

    // Sign with a separate deterministic key so the test verifies the new
    // `convert_ckb_state` output rather than relying on externally
    // generated signatures.
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::signature::Signer as Signer2;
    use k256::ecdsa::SigningKey as SigningKey2;

    let sk2 = SigningKey2::from_bytes((&[0x22u8; 32]).into()).expect("invalid sk2");
    let verifying_key2 = sk2.verifying_key();
    let pk_point2 = verifying_key2.to_encoded_point(true);
    let pk_bytes_vec2 = pk_point2.as_bytes().to_vec();
    let pubkey_bytes2: [Byte; 33] = pk_bytes_vec2
        .iter()
        .map(|b| Byte::from(*b))
        .collect::<Vec<Byte>>()
        .try_into()
        .unwrap();
    SEC1EncodedPubKey::new_builder().set(pubkey_bytes2).build();

    let ck_dist = AnyBalancesUnion::CKByteDistribution(
        CKByteDistribution::new_builder()
            .set([ck_a.pack(), ck_b.pack()])
            .build(),
    );

    // ETH asset & distribution
    let chain_id_u128 = u128_le_as_uint128(eth_chain_id);
    let eth_addr = eth_address_from_hex(eth_addr_hex);
    let eth_asset = ETHAsset::new_builder()
        .chain_id(chain_id_u128)
        .asset_address(eth_addr)
        .build();

    let eth_dist = ETHDistribution::new_builder()
        .nth0(u128_le_as_uint128(eth_a))
        .nth1(u128_le_as_uint128(eth_b))
        .build();

    let eth_balances = AnyBalancesUnion::ETHBalances(
        ETHBalances::new_builder()
            .asset(eth_asset)
            .distribution(eth_dist)
            .build(),
    );

    // Locked: push a default SubAlloc (keeps Molecule happy; convert() ignores it)
    let locked = LockedBalances::new_builder()
        .push(SubAlloc::new_builder().build())
        .build();

    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(AnyBalances::new_builder().set(ck_dist).build())
                .push(AnyBalances::new_builder().set(eth_balances).build())
                .build(),
        )
        .locked(locked)
        .build();

    let channel_state = ChannelState::new_builder()
        .channel_id(Byte32::from_slice(&channel_id_bytes).unwrap())
        .balances(balances)
        .is_final(Bool::from_bool(true))
        .version(version.pack())
        .build();
    let state_eth = convert_ckb_state(&channel_state);
    println!("State: {:?}", state_eth);
    let state_abi_encoded = state_eth.abi_encode();
    println!("Encoded: {:?}", state_abi_encoded);
    let msg_hash = ethereum_message_hash(&state_abi_encoded);
    println!("Hash: {:?}", msg_hash);
    let sig2: k256::ecdsa::Signature = sk2.sign_prehash(&msg_hash).expect("sign failed");
    let sig_bytes2: Bytes = sig2.to_der().as_bytes().to_vec().into();
    verify_signature(&msg_hash, &sig_bytes2, pk_point2.as_bytes()).expect("valid signature");
}

// Build a deterministic secp256k1 keypair from a seed byte, returning the signing
// key together with its SEC1-compressed public key (raw bytes + molecule type).
fn sec1_keypair(seed: u8) -> (k256::ecdsa::SigningKey, [u8; 33], SEC1EncodedPubKey) {
    let sk = k256::ecdsa::SigningKey::from_bytes((&[seed; 32]).into()).expect("invalid sk");
    let point = sk.verifying_key().to_encoded_point(true);
    let raw: [u8; 33] = point.as_bytes().try_into().expect("33-byte sec1 pubkey");
    let bytes: [Byte; 33] = raw
        .iter()
        .map(|b| Byte::from(*b))
        .collect::<Vec<Byte>>()
        .try_into()
        .unwrap();
    (sk, raw, SEC1EncodedPubKey::new_builder().set(bytes).build())
}

fn mk_participant(pub_key: SEC1EncodedPubKey, tag: u8) -> Participant {
    Participant::new_builder()
        .payment_script_hash(Byte32::from_slice(&[tag; 32]).unwrap())
        .payment_min_capacity(1_000u64.pack())
        .unlock_script_hash(Byte32::from_slice(&[tag.wrapping_add(1); 32]).unwrap())
        .pub_key(pub_key)
        .build()
}

fn mk_params(
    party_a: Participant,
    party_b: Participant,
    coordinator: Option<SEC1EncodedPubKey>,
) -> ChannelParameters {
    ChannelParameters::new_builder()
        .party_a(party_a)
        .party_b(party_b)
        .nonce(Byte32::from_slice(&[7u8; 32]).unwrap())
        .challenge_duration(1234u64.pack())
        .is_ledger_channel(Bool::from_bool(true))
        .is_virtual_channel(Bool::from_bool(false))
        .coordinator(Coordinator::new_builder().set(coordinator).build())
        .build()
}

fn ckb_only_state() -> ChannelState {
    let ck = AnyBalancesUnion::CKByteDistribution(
        CKByteDistribution::new_builder()
            .set([10u64.pack(), 11u64.pack()])
            .build(),
    );
    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(AnyBalances::new_builder().set(ck).build())
                .build(),
        )
        .locked(LockedBalances::default())
        .build();
    ChannelState::new_builder()
        .channel_id(Byte32::from_slice(&[1u8; 32]).unwrap())
        .balances(balances)
        .version(1u64.pack())
        .is_final(Bool::from_bool(false))
        .build()
}

fn ckb_eth_state() -> ChannelState {
    let ck = AnyBalancesUnion::CKByteDistribution(
        CKByteDistribution::new_builder()
            .set([10u64.pack(), 11u64.pack()])
            .build(),
    );
    let eth = AnyBalancesUnion::ETHBalances(
        ETHBalances::new_builder()
            .asset(
                ETHAsset::new_builder()
                    .chain_id(u128_le_as_uint128(1337))
                    .asset_address(eth_address_from_hex(
                        "4E1D65a1E558029058903528140438802a6B5dfC",
                    ))
                    .build(),
            )
            .distribution(
                ETHDistribution::new_builder()
                    .nth0(u128_le_as_uint128(5))
                    .nth1(u128_le_as_uint128(6))
                    .build(),
            )
            .build(),
    );
    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(AnyBalances::new_builder().set(ck).build())
                .push(AnyBalances::new_builder().set(eth).build())
                .build(),
        )
        .locked(LockedBalances::default())
        .build();
    ChannelState::new_builder()
        .channel_id(Byte32::from_slice(&[1u8; 32]).unwrap())
        .balances(balances)
        .version(1u64.pack())
        .is_final(Bool::from_bool(false))
        .build()
}

// Validates the cross-chain coordinated-settlement primitives in perun-common:
// the coordinator is encoded into Params (changing the channel id), multi-ledger
// states are detected, eligibility follows MultiLedger.sol, and the coordinator
// signature verifies with the same EIP-191 scheme as participant signatures.
#[test]
fn test_coordinator_encoding_and_multiledger() {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let (_, _, pk_a) = sec1_keypair(0x11);
    let (_, _, pk_b) = sec1_keypair(0x12);
    let (coord_sk, coord_raw, coord_pk) = sec1_keypair(0x33);

    let part_a = mk_participant(pk_a.clone(), 0xA0);
    let part_b = mk_participant(pk_b.clone(), 0xB0);

    let params_with = mk_params(part_a.clone(), part_b.clone(), Some(coord_pk.clone()));
    let params_without = mk_params(part_a, part_b, None);

    // (1) The coordinator field in Params encodes as the eth address derived from
    // the coordinator's pubkey; absent, it is address(0).
    let derived = eth_address_from_sec1_pubkey(&coord_raw).expect("derive eth addr");
    assert_eq!(
        convert_params(&params_with).coordinator.as_slice(),
        derived.as_slice(),
        "coordinator must encode as the derived eth address"
    );
    assert_eq!(
        convert_params(&params_without).coordinator.as_slice(),
        &[0u8; 20],
        "no coordinator must encode as address(0)"
    );

    // (2) Adding the coordinator changes the ABI-encoded params (hence the channel
    // id keccak256(abi_encode(params))), keeping CKB <-> Ethereum ids consistent.
    assert_ne!(
        convert_params(&params_with).abi_encode(),
        convert_params(&params_without).abi_encode(),
        "coordinator must affect the channel id encoding"
    );

    // (3) Multi-ledger detection mirrors MultiLedger.isMultiLedgerState.
    let multi = ckb_eth_state();
    let single = ckb_only_state();
    assert!(is_multi_ledger_state(&multi), "CKB+ETH is multi-ledger");
    assert!(!is_multi_ledger_state(&single), "CKB-only is single-ledger");

    // (4) Eligibility = coordinator configured AND multi-ledger.
    assert!(is_coordinated_eligible(&params_with, &multi));
    assert!(!is_coordinated_eligible(&params_without, &multi));
    assert!(!is_coordinated_eligible(&params_with, &single));

    // (5) The coordinator signature verifies with the same scheme as participants.
    let msg_hash = ethereum_message_hash(&convert_ckb_state(&multi).abi_encode());
    let sig: k256::ecdsa::Signature = coord_sk.sign_prehash(&msg_hash).expect("sign");
    let sig_bytes: Bytes = sig.to_der().as_bytes().to_vec().into();
    verify_coordinator_sig(&sig_bytes, &multi, &coord_pk).expect("coordinator sig must verify");
    assert!(
        verify_coordinator_sig(&sig_bytes, &multi, &pk_a).is_err(),
        "a non-coordinator key must not verify"
    );
}

mod ckb_keys {
    use crate::perun::Account;
    use crate::perun::TestAccount;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::PublicKey;
    pub fn generate_ckb_keypair() -> (SigningKey, PublicKey) {
        let acc_name = "alice".to_string();
        let account = TestAccount::new_with_random_key(acc_name);
        let pubkey = account.public_key();
        let signing_key = account.sk.clone();
        (signing_key, pubkey)
    }

    pub fn print_ckb_keypair() {
        let (signing_key, public_key) = generate_ckb_keypair();
        println!(
            "CKB Private Key (hex): 0x{}",
            hex::encode(signing_key.to_bytes())
        );
        println!(
            "CKB Public Key  (hex): 0x{}",
            hex::encode(public_key.to_encoded_point(false).as_bytes())
        );
    }
}

#[test]
fn test_generate_ckb_keys() {
    ckb_keys::print_ckb_keypair();
}

#[test]
// TODO: Add mutator to channel state that can be passed to dispute, and close.
fn channel_test_bench() -> Result<(), perun::Error> {
    let res = [
        test_successful_funding_with_udt_and_eth,
        test_funding_abort,
        test_successful_funding_with_udt,
        test_successful_funding_without_udt,
        test_early_force_close,
        test_close,
        test_close_with_eth,
        test_force_close,
        test_multiple_disputes,
        test_multiple_disputes_same_version,
        test_multi_asset_payment,
        test_multi_asset_abort,
        test_multi_asset_abort_zero_sudt_balance,
        test_multi_asset_force_close,
        test_dispute_wrong_signer,
        test_dispute_corrupted_signature,
        test_dispute_version_regression,
        test_dispute_inflated_balances,
        test_eth_payment_and_force_close,
        test_coordinate_then_force_close,
        test_force_close_requires_coordinate,
        test_coordinate_wrong_coordinator_rejected,
        test_channel_id_matches_ethereum,
    ]
    .iter()
    .map(|test| {
        let mut context = Rc::new(Mutex::new(RefCell::new(Context::default())));
        let pe = perun::harness::Env::new(context.clone(), MAX_CYCLES, CHALLENGE_DURATION_MS)
            .expect("preparing environment");
        test(context, &pe)
    })
    .collect::<Vec<_>>();
    res.into_iter().collect()
}

#[test]
fn channel_vc_test_bench() -> Result<(), perun::Error> {
    let res = [
        test_vc_start,
        test_vc_start2,
        test_vc_progress_no_update,
        test_vc_progress_update1,
        test_vc_progress_update2,
        test_vc_merge,
        test_vc_close1,
        test_close_with_locked_funds,
        test_normal_dispute_with_locked_funds,
        test_vc_close2,
        test_vc_happy,
        test_vc_happy_multi_asset,
        test_vc_happy_with_merge,
        test_vc_happy_multi_asset_with_merge,
        test_vc_happy_multi_asset_eth,
        test_vc_happy_multi_asset_eth_with_merge,
        test_vc_coordinate_then_close,
        test_vc_close_requires_coordinate,
        test_vc_no_coordinator_settles_via_timelock,
    ]
    .iter()
    .map(|test| {
        let context = Rc::new(Mutex::new(RefCell::new(Context::default())));
        let pe = perun::harness::Env::new(context.clone(), MAX_CYCLES, CHALLENGE_DURATION_MS)
            .expect("preparing environment");
        test(context, &pe)
    })
    .collect::<Vec<_>>();
    res.into_iter().collect()
}

fn create_channel_test(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
    parts: &[perun::TestAccount],
    test: impl Fn(&mut perun::channel::Channel<perun::State>) -> Result<(), perun::Error>,
) -> Result<(), perun::Error> {
    let mut chan = perun::channel::Channel::new(context, env, parts);
    test(&mut chan)
}

fn create_vc_channel_test(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
    parts_ai: &[perun::TestAccount],
    parts_bi: &[perun::TestAccount],
    test: impl Fn(
        &mut perun::channel::Channel<perun::State>,
        &mut perun::channel::Channel<perun::State>,
    ) -> Result<(), perun::Error>,
) -> Result<(), perun::Error> {
    // Create channels
    let mut chan_ai = perun::channel::Channel::new(context.clone(), env, parts_ai);
    let mut chan_bi = perun::channel::Channel::new(context.clone(), env, parts_bi);

    // Run the test function with mutable references
    test(&mut chan_ai, &mut chan_bi)
}

fn test_funding_abort(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding_timeout = 10;
    let funding = [
        Capacity::bytes(1000)?.as_u64(),
        Capacity::bytes(1000)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.delay(funding_timeout);

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_without_udt(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_with_udt_and_eth(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let asset_funding = [20u128, 30u128];
    let eth_funding = [5u128, 10u128]; // ETH amounts
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();
    // FundingAgreement with both UDT and ETH assets
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_with_udt(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_close_with_eth(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let asset_funding = [20u128, 30u128]; // UDT amounts
    let eth_funding = [5u128, 10u128]; // ETH amounts

    // Calculate ETH max capacity (sum of eth_funding amounts as u64)
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    // Construct FundingAgreement with both UDT and ETH assets
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(bob).dispute().expect("invalid channel dispute");

        chan.delay(env.challenge_duration);

        chan.with(bob).force_close().expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_early_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(bob).dispute().expect("invalid channel dispute");

        chan.with(bob)
            .invalid()
            .force_close()
            .expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multiple_disputes_same_version(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .valid()
            .dispute()
            .expect("disputing channel");

        chan.with(bob)
            .invalid()
            .dispute()
            .expect("disputing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multiple_disputes(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .valid()
            .dispute()
            .expect("disputing channel");

        chan.with(bob)
            .valid()
            .update(bump_version())
            .dispute()
            .expect("disputing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multi_asset_payment(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.update(pay_ckbytes(Direction::AtoB, 50));
        chan.update(pay_sudt(Direction::BtoA, 10, 0));

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

pub fn test_multi_asset_abort(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [Capacity::bytes(0)?.as_u64(), Capacity::bytes(0)?.as_u64()];
    let asset_funding = [30u128, 20u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

pub fn test_multi_asset_abort_zero_sudt_balance(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [Capacity::bytes(0)?.as_u64(), Capacity::bytes(0)?.as_u64()];
    let asset_funding = [0u128, 0u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

fn test_multi_asset_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.update(pay_ckbytes(Direction::AtoB, 50));
        chan.update(pay_sudt(Direction::BtoA, 10, 0));

        chan.with(bob).dispute().expect("disputing channel");

        chan.delay(env.challenge_duration);

        chan.with(bob).force_close().expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_vc_start(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_START");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// register a disupte for a lc state without locked funds
// followed by a dispute for the virtual channel with  lc state having locked funds
fn test_vc_start2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_START2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            chan_ai.with(alice).dispute().expect("invalid dispute");

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab)
                .expect("invalid vc_start");
            chan_ai.assert();
            Ok(())
        },
    )
}

fn test_vc_progress_no_update(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_NO_UPDATE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            println!("opening vc dispute no progress on C_BI using Ingrid");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// state update in vc but no update in lc
fn test_vc_progress_update1(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_UPDATE1");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// state updates for both lc and vc
fn test_vc_progress_update2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_UPDATE2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));
            //simulate state update for lc
            chan_ai.with(alice).update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_lc_update(&mut vc_ab)
                .expect("vc_lc_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    let delay = 10u64;

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start by alice using C_AI");
            chan_bi.delay(delay);
            chan_bi
                .with(bob)
                .vc_start(&mut vc_ab_2)
                .expect("vc_start by bob using C_BI");

            chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_close1(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_CLOSE1");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_with_dir = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_with_dir)
                .expect("vc_close1");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// test that contract doesn't allow to close a lc cell with locked funds.
fn test_close_with_locked_funds(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_CLOSE_WITH_LOCKED_FUNDS");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);

            chan_ai
                .with(alice)
                .invalid()
                .finalize()
                .close()
                .expect("closing channel");

            chan_ai.assert();
            Ok(())
        },
    )
}

// test that contract doesn't allow to register a normal dispute for a lc state having locked funds
fn test_normal_dispute_with_locked_funds(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_NORMAL_DISPUTE_WITH_LOCKED_FUNDS");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_ai
                .with(alice)
                .invalid()
                .dispute()
                .expect("invalid dispute");
            chan_ai.assert();
            Ok(())
        },
    )
}

fn test_vc_close2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_CLOSE2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [50u128, 50u128];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let asset_funding_vc = [20u128, 20u128];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(asset_funding_vc.iter().cloned())
            .collect(),
    );
    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");
            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));
            vc_ab.update(pay_sudt(Direction::AtoB, 10, 0));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_with_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };
    let delay = 10u64;
    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_WITH_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start");
            chan_bi.delay(delay);

            chan_bi.with(bob).vc_start(&mut vc_ab_2).expect("vc_start");

            let result = chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");

            vc_ab_1.set_cell(result);

            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab_1)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab_1.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab_1)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab_1, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab_1, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset_with_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [50u128, 50u128];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let asset_funding_vc = [20u128, 20u128];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(asset_funding_vc.iter().cloned())
            .collect(),
    );
    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET_WITH_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );

            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start");
            chan_bi.delay(10u64);
            chan_bi.with(bob).vc_start(&mut vc_ab_2).expect("vc_start");

            let result = chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");
            vc_ab_1.set_cell(result);

            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab_1)
                .expect("vc_progress_no_update");
            // simulate state update for vc
            vc_ab_1.update(pay_ckbytes(Direction::AtoB, 30));
            vc_ab_1.update(pay_sudt(Direction::AtoB, 10, 0));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab_1)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab_1, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab_1, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// A cross-chain (multi-ledger) virtual channel must be moved into the
// coordinated phase before it can be force-closed. This mirrors Ethereum's
// `coordinateRecursive`: a single transaction coordinates a parent ledger
// channel together with its virtual channel, and only afterwards may the funds
// be force-closed. The flow disputes both parents, registers the canonical VC
// state, then runs a recursive Coordinate tx per parent (each carrying a
// coordinator-certified canonical LC and VC state) before closing.
fn test_vc_coordinate_then_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);
    let coordinator_acc = random::account("coordinator");
    // The coordinator key embedded in both ledger-channel and virtual-channel
    // parameters. The same key certifies the canonical state on every cell.
    let coordinator_client = perun::test::Client::new(
        u8::MAX,
        coordinator_acc.name.clone(),
        coordinator_acc.sk.clone(),
    );
    let coordinator_pubkey = coordinator_client.sec1_pubkey();

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let sudt_funding = [50u128, 50u128];
    let eth_funding = [100u128, 100u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];
    let sudt_funding_vc = [20u128, 20u128];
    let eth_funding_vc = [40u128, 40u128];
    let eth_chain_id_vc = eth_funding_vc.iter().cloned().sum::<u128>();

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_ai
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_assets(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_bi
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(sudt_funding_vc.iter().cloned())
            .collect(),
        eth_chain_id_vc,
        parts_ab
            .iter()
            .cloned()
            .zip(eth_funding_vc.iter().cloned())
            .collect(),
    );

    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_COORDINATE_THEN_CLOSE");
            chan_ai.with_coordinator(&coordinator_acc);
            chan_bi.with_coordinator(&coordinator_acc);

            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new_with_coordinator(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
                Some(coordinator_pubkey.clone()),
            );
            drop(ctx);

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // Update with both SUDT and ETH payments.
            vc_ab.update(pay_ckbytes(Direction::AtoB, 20));
            vc_ab.update(pay_sudt(Direction::AtoB, 10, 0));
            vc_ab.update(pay_eth(Direction::AtoB, 15, 0));

            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            // Both dispute windows expire, then each parent ledger channel is
            // coordinated together with the shared virtual channel.
            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);

            chan_ai
                .with(alice)
                .vc_coordinate(&mut vc_ab)
                .expect("recursive coordinate (parent AI + VC)");
            chan_bi
                .with(ingrid)
                .vc_coordinate(&mut vc_ab)
                .expect("recursive coordinate (parent BI + VC)");

            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");

            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// A multi-ledger virtual channel that has NOT been coordinated must not be
// force-closeable: vc_close1 is rejected with CoordinatedSettlementRequired.
fn test_vc_close_requires_coordinate(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);
    let coordinator_acc = random::account("coordinator");
    let coordinator_client = perun::test::Client::new(
        u8::MAX,
        coordinator_acc.name.clone(),
        coordinator_acc.sk.clone(),
    );
    let coordinator_pubkey = coordinator_client.sec1_pubkey();

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let sudt_funding = [50u128, 50u128];
    let eth_funding = [100u128, 100u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];
    let sudt_funding_vc = [20u128, 20u128];
    let eth_funding_vc = [40u128, 40u128];
    let eth_chain_id_vc = eth_funding_vc.iter().cloned().sum::<u128>();

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_ai
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_assets(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_bi
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(sudt_funding_vc.iter().cloned())
            .collect(),
        eth_chain_id_vc,
        parts_ab
            .iter()
            .cloned()
            .zip(eth_funding_vc.iter().cloned())
            .collect(),
    );

    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_CLOSE_REQUIRES_COORDINATE");
            chan_ai.with_coordinator(&coordinator_acc);
            chan_bi.with_coordinator(&coordinator_acc);

            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");
            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");
            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");
            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new_with_coordinator(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
                Some(coordinator_pubkey.clone()),
            );
            drop(ctx);

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);

            // No coordinate has been performed, so closing the multi-ledger
            // virtual channel must be rejected.
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai.with(alice).invalid();
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1 without coordinate must be rejected");

            chan_ai.assert();
            Ok(())
        },
    )
}

// vc_eth_funding_agreements builds the (AI, BI, AB) cross-asset (CKB+SUDT+ETH)
// funding agreements shared by the multi-asset virtual-channel tests: the two
// parent ledger channels (AI, BI) and the virtual channel (AB).
fn vc_eth_funding_agreements(
    env: &perun::harness::Env,
    parts_ai: &[perun::TestAccount],
    parts_bi: &[perun::TestAccount],
    parts_ab: &[perun::TestAccount],
) -> Result<
    (
        test::FundingAgreement,
        test::FundingAgreement,
        test::FundingAgreement,
    ),
    perun::Error,
> {
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let sudt_funding = [50u128, 50u128];
    let eth_funding = [100u128, 100u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];
    let sudt_funding_vc = [20u128, 20u128];
    let eth_funding_vc = [40u128, 40u128];
    let eth_chain_id_vc = eth_funding_vc.iter().cloned().sum::<u128>();

    let mk = |parts: &[perun::TestAccount],
              cap: &[u64; 2],
              sudt: &[u128; 2],
              eth_cid: u128,
              eth: &[u128; 2]| {
        test::FundingAgreement::new_with_capacities_and_assets(
            parts.iter().cloned().zip(cap.iter().cloned()).collect(),
            &env.sample_udt_script,
            env.sample_udt_max_cap.as_u64(),
            parts.iter().cloned().zip(sudt.iter().cloned()).collect(),
            eth_cid,
            parts.iter().cloned().zip(eth.iter().cloned()).collect(),
        )
    };

    Ok((
        mk(
            parts_ai,
            &funding,
            &sudt_funding,
            eth_chain_id,
            &eth_funding,
        ),
        mk(
            parts_bi,
            &funding,
            &sudt_funding,
            eth_chain_id,
            &eth_funding,
        ),
        mk(
            parts_ab,
            &funding_vc,
            &sudt_funding_vc,
            eth_chain_id_vc,
            &eth_funding_vc,
        ),
    ))
}

// A virtual channel that carries NO coordinator must still be settleable when it
// is nested inside a coordinated cross-chain ledger channel: the ledger channels
// are coordinated (LC-only, the VC is not bundled), and the VC is force-closed
// via its own refutation-window time lock. This exercises the decoupled
// force-close gate (LC leg coordinated, VC leg time-locked).
fn test_vc_no_coordinator_settles_via_timelock(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);
    let coordinator_acc = random::account("coordinator");

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let (funding_agreement_ai, funding_agreement_bi, funding_agreement_ab) =
        vc_eth_funding_agreements(env, &parts_ai, &parts_bi, &parts_ab)?;

    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_NO_COORDINATOR_SETTLES_VIA_TIMELOCK");
            // The parent ledger channels are coordinated (cross-chain), but the
            // virtual channel itself carries no coordinator.
            chan_ai.with_coordinator(&coordinator_acc);
            chan_bi.with_coordinator(&coordinator_acc);

            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");
            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");
            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");
            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            // VirtualChannel::new (not new_with_coordinator) → the VC has no
            // coordinator configured.
            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            vc_ab.update(pay_ckbytes(Direction::AtoB, 20));
            vc_ab.update(pay_sudt(Direction::AtoB, 10, 0));
            vc_ab.update(pay_eth(Direction::AtoB, 15, 0));

            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            // Coordinate each parent ledger channel on its own (the VC is NOT
            // bundled, because a VC without a coordinator cannot be coordinated).
            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);

            chan_ai
                .with(alice)
                .coordinate()
                .expect("coordinate parent AI (ledger channel only)");
            chan_bi
                .with(ingrid)
                .coordinate()
                .expect("coordinate parent BI (ledger channel only)");

            // The virtual channel's own refutation window must elapse before it
            // can be force-closed via the time-lock path.
            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);
            chan_bi.delay(env.challenge_duration);

            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1 (vc settled via time lock)");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2 (vc settled via time lock)");

            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset_eth(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let sudt_funding = [50u128, 50u128];
    let eth_funding = [100u128, 100u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];
    let sudt_funding_vc = [20u128, 20u128];
    let eth_funding_vc = [40u128, 40u128];
    let eth_chain_id_vc = eth_funding_vc.iter().cloned().sum::<u128>();

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_ai
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_assets(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_bi
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(sudt_funding_vc.iter().cloned())
            .collect(),
        eth_chain_id_vc,
        parts_ab
            .iter()
            .cloned()
            .zip(eth_funding_vc.iter().cloned())
            .collect(),
    );

    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET_ETH");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // Update with both SUDT and ETH payments
            vc_ab.update(pay_ckbytes(Direction::AtoB, 20));
            vc_ab.update(pay_sudt(Direction::AtoB, 10, 0));
            vc_ab.update(pay_eth(Direction::AtoB, 15, 0));

            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");

            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset_eth_with_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let sudt_funding = [50u128, 50u128];
    let eth_funding = [100u128, 100u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];
    let sudt_funding_vc = [20u128, 20u128];
    let eth_funding_vc = [40u128, 40u128];
    let eth_chain_id_vc = eth_funding_vc.iter().cloned().sum::<u128>();

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_ai
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_assets(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(sudt_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts_bi
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_assets(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(sudt_funding_vc.iter().cloned())
            .collect(),
        eth_chain_id_vc,
        parts_ab
            .iter()
            .cloned()
            .zip(eth_funding_vc.iter().cloned())
            .collect(),
    );

    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    let delay = 10u64;

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET_ETH_WITH_MERGE");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            let owner_participants_ai = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants_ai.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );

            let owner_participants_bi = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants_bi.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );
            drop(ctx);

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start");
            chan_bi.delay(delay);

            chan_bi.with(bob).vc_start(&mut vc_ab_2).expect("vc_start");

            let result = chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");

            vc_ab_1.set_cell(result);

            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab_1)
                .expect("vc_progress_no_update");

            // Update with both SUDT and ETH payments
            vc_ab_1.update(pay_ckbytes(Direction::AtoB, 30));
            vc_ab_1.update(pay_sudt(Direction::AtoB, 15, 0));
            vc_ab_1.update(pay_eth(Direction::AtoB, 20, 0));

            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab_1)
                .expect("vc_update_only");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);

            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab_1, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab_1, &idx_map_parent2)
                .expect("vc_close2");

            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// =============================================================================
// Security tests: signature forgery, version regression, balance inflation
// =============================================================================

fn test_dispute_wrong_signer(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    let carol = random::account("carol");
    let carol_client = test::Client::new(2, "carol".into(), carol.sk.clone());

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        let alice_client = test::Client::new(0, "alice".into(), parts[0].sk.clone());
        let sig_a = alice_client.sign(chan.state().state())?;
        let sig_carol = carol_client.sign(chan.state().state())?;

        chan.with(alice)
            .invalid()
            .dispute_with_custom_sigs([sig_a, sig_carol])
            .expect("dispute with wrong signer must fail");
        Ok(())
    })
}

fn test_dispute_corrupted_signature(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        let alice_client = test::Client::new(0, "alice".into(), parts[0].sk.clone());
        let bob_client = test::Client::new(1, "bob".into(), parts[1].sk.clone());
        let sig_a = alice_client.sign(chan.state().state())?;
        let mut sig_b = bob_client.sign(chan.state().state())?;
        if sig_b.len() > 10 {
            sig_b[10] ^= 0xff;
        }

        chan.with(alice)
            .invalid()
            .dispute_with_custom_sigs([sig_a, sig_b])
            .expect("dispute with corrupted signature must fail");
        Ok(())
    })
}

fn test_dispute_version_regression(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .valid()
            .update(bump_version())
            .update(bump_version())
            .dispute()
            .expect("valid dispute at version 2");

        chan.with(bob)
            .invalid()
            .update(set_version(1))
            .dispute()
            .expect("dispute with version regression must fail");
        Ok(())
    })
}

fn test_dispute_inflated_balances(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .invalid()
            .update(inflate_ckbytes(0, Capacity::bytes(50)?.as_u64()))
            .dispute()
            .expect("dispute with inflated balances must fail");
        Ok(())
    })
}

fn test_eth_payment_and_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let eth_funding = [50u128, 50u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .update(pay_eth(Direction::AtoB, 20, 0))
            .dispute()
            .expect("dispute after ETH payment");

        chan.delay(env.challenge_duration);

        chan.with(alice)
            .force_close()
            .expect("force close after ETH payment");

        chan.assert();
        Ok(())
    })
}

// Builds a multi-ledger (CKB + UDT + ETH) funding agreement used by the
// coordinated-settlement tests.
fn coordinated_funding_agreement(
    env: &perun::harness::Env,
    parts: &[perun::TestAccount],
) -> Result<test::FundingAgreement, perun::Error> {
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let eth_funding = [50u128, 50u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();
    Ok(test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    ))
}

// Happy path: a coordinated multi-ledger channel can be force-closed after the
// coordinator has certified the canonical state.
fn test_coordinate_then_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let coordinator = random::account("coordinator");
    let funding_agreement = coordinated_funding_agreement(env, &parts)?;

    create_channel_test(context, env, &parts, |chan| {
        chan.with_coordinator(&coordinator);
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .update(pay_eth(Direction::AtoB, 20, 0))
            .dispute()
            .expect("dispute after ETH payment");

        chan.delay(env.challenge_duration);

        chan.with(alice)
            .coordinate()
            .expect("coordinate the multi-ledger channel");

        chan.with(alice)
            .force_close()
            .expect("force close after coordination");

        chan.assert();
        Ok(())
    })
}

// A multi-ledger channel with a coordinator must NOT be force-closable until it
// has been coordinated (mirrors Ethereum's "coordinated settlement required").
fn test_force_close_requires_coordinate(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let coordinator = random::account("coordinator");
    let funding_agreement = coordinated_funding_agreement(env, &parts)?;

    create_channel_test(context, env, &parts, |chan| {
        chan.with_coordinator(&coordinator);
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .update(pay_eth(Direction::AtoB, 20, 0))
            .dispute()
            .expect("dispute after ETH payment");

        chan.delay(env.challenge_duration);

        // Skipping coordination, the force close must be rejected.
        chan.with(alice)
            .invalid()
            .force_close()
            .expect("force close without coordination must be rejected");

        Ok(())
    })
}

// A coordinate transaction signed by a key other than the channel's configured
// coordinator must be rejected.
fn test_coordinate_wrong_coordinator_rejected(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let coordinator = random::account("coordinator");
    let mallory = random::account("mallory");
    let funding_agreement = coordinated_funding_agreement(env, &parts)?;

    create_channel_test(context, env, &parts, |chan| {
        chan.with_coordinator(&coordinator);
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .update(pay_eth(Direction::AtoB, 20, 0))
            .dispute()
            .expect("dispute after ETH payment");

        chan.delay(env.challenge_duration);

        // A coordinator signature from the wrong key must be rejected.
        let wrong = perun::test::Client::new(u8::MAX, mallory.name.clone(), mallory.sk.clone());
        chan.with(alice).invalid();
        chan.coordinate_with_coordinator(&wrong)
            .expect("coordinate with wrong coordinator key must be rejected");

        Ok(())
    })
}

fn test_channel_id_matches_ethereum(
    _context: Rc<Mutex<RefCell<Context>>>,
    _env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::CKByteDistribution(
                            CKByteDistribution::new_builder()
                                .set([100u64.pack(), 200u64.pack()])
                                .build(),
                        ))
                        .build(),
                )
                .build(),
        )
        .locked(
            LockedBalances::new_builder()
                .push(SubAlloc::new_builder().build())
                .build(),
        )
        .build();

    let state = ChannelState::new_builder()
        .channel_id(Byte32::zero())
        .balances(balances)
        .version(1u64.pack())
        .is_final(Bool::from_bool(false))
        .build();

    let state_eth = convert_ckb_state(&state);
    let encoded = state_eth.abi_encode();
    let hash = ethereum_message_hash(&encoded);

    assert_eq!(hash.len(), 32);
    let hash2 = ethereum_message_hash(&convert_ckb_state(&state).abi_encode());
    assert_eq!(hash, hash2, "state encoding must be deterministic");
    assert!(
        encoded.iter().any(|&b| b != 0),
        "ABI encoding must not be empty"
    );
    assert!(encoded.len() > 64, "ABI encoding must contain actual data");
    Ok(())
}
