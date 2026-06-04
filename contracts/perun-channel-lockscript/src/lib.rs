#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

use ckb_std::default_alloc;
ckb_std::entry!(program_entry);
default_alloc!();

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_cell_lock_hash, load_cell_type, load_script, load_witness_args},
    syscalls::SysError,
};
use perun_common::{
    channels::is_coordinator_configured,
    error::Error,
    perun_types::{ChannelConstants, ChannelWitness, ChannelWitnessUnion},
};

// The perun-channel-lockscript (pcls) is used to lock access to interacting with a channel and is attached as lock script
// to the channel-cell (the cell which uses the perun-channel-type-script (pcts) as its type script).
// A channel defines two participants, each of which has their own unlock_script_hash (also defined in the ChannelConstants.params.{party_a,party_b}).
// The pcls allows a transaction to interact with the channel, if at least one input cell is present with:
// - cell's lock script hash == unlock_script_hash of party_a or
// - cell's lock script hash == unlock_script_hash of party_b
// We recommend using the secp256k1_blake160_sighash_all script as unlock script and corresponding payment args for the participants.
//
// Note: This means, that each participant needs to use a secp256k1_blake160_sighash_all as input to interact with the channel.
// This should not be a substantial restriction, since a payment input will likely be used anyway (e.g. for funding or fees).
//
// Coordinated settlement: when the channel has a coordinator configured (params.coordinator is set),
// the coordinator is an off-channel third party that drives the `coordinate` action. Its input cell is
// locked by neither participant's unlock_script_hash, so the participant check above does not match it.
// To let the coordinator submit the Coordinate transaction itself (funding it from its own cell), the
// pcls additionally accepts a transaction whose channel input carries a Coordinate redeemer, but only
// for channels that actually have a coordinator configured. This is safe because the pcts verifies the
// coordinator's signature on the canonical state in the same transaction, so a forged coordinate that
// lacks the real coordinator (and participant) signatures can never pass the pcts.

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,         // Success
        Err(e) => e.into(), // Failure
    }
}

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    // return an error if args is invalid
    if !args.is_empty() {
        return Err(Error::PCLSWithArgs);
    }

    // locate the ChannelConstants in the type script of the input cell.
    // the best practice is to loop all the input cells in the group
    for i in 0.. {
        // Loop over all input cells.
        let type_script = match load_cell_type(i, Source::GroupInput) {
            Ok(Some(script)) => script,
            Ok(None) => {
                debug!("Error: Type script not found");
                return Err(Error::PCTSNotFound);
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
        let type_script_args: Bytes = type_script.args().unpack();

        let constants = ChannelConstants::from_slice(&type_script_args)
            .expect("unable to parse args as channel parameters");
        let params = constants.params();

        let is_participant = verify_is_participant(
            &params.party_a().unlock_script_hash().unpack(),
            &params.party_b().unlock_script_hash().unpack(),
        )?;

        if is_participant {
            continue;
        }

        // The transaction is not authorized by a participant. If the channel has a
        // coordinator configured, the coordinator may still interact with the channel
        // cell to carry out a Coordinate action (it funds the transaction from its own
        // cell, which matches neither participant). We accept this only when the channel
        // input's witness is a Coordinate redeemer; the pcts validates the coordinator's
        // signature on the canonical state in the same transaction.
        if is_coordinator_configured(&params) && witness_is_coordinate(i) {
            debug!("coordinator-authorized Coordinate transaction accepted");
            continue;
        }

        return Err(Error::NotParticipant);
    }

    return Ok(());
}

/// witness_is_coordinate reports whether the channel input at the given group input
/// index carries a Coordinate redeemer in its witness `input_type` field. A missing
/// or malformed witness is treated as "not a coordinate" (returns false), so the
/// caller falls back to requiring a participant input.
fn witness_is_coordinate(group_input_index: usize) -> bool {
    let witness_args = match load_witness_args(group_input_index, Source::GroupInput) {
        Ok(witness_args) => witness_args,
        Err(_) => return false,
    };
    let witness_bytes: Bytes = match witness_args.input_type().to_opt() {
        Some(input_type) => input_type.unpack(),
        None => return false,
    };
    match ChannelWitness::from_slice(&witness_bytes) {
        Ok(channel_witness) => {
            matches!(channel_witness.to_enum(), ChannelWitnessUnion::Coordinate(_))
        }
        Err(_) => false,
    }
}

/// check_is_participant checks if the current transaction is executed by a channel participant.
/// It does so by looking for an input cell with the same lock script hash as the unlock_script_hash
pub fn verify_is_participant(
    unlock_script_hash_a: &[u8; 32],
    unlock_script_hash_b: &[u8; 32],
) -> Result<bool, Error> {
    for i in 0.. {
        // Loop over all input cells.
        let cell_lock_script_hash = match load_cell_lock_hash(i, Source::Input) {
            Ok(lock_hash) => lock_hash,
            Result::Err(SysError::IndexOutOfBound) => return Ok(false),
            Result::Err(err) => return Result::Err(err.into()),
        };
        if cell_lock_script_hash[..] == unlock_script_hash_a[..]
            || cell_lock_script_hash[..] == unlock_script_hash_b[..]
        {
            return Ok(true);
        }
    }
    Ok(false)
}
