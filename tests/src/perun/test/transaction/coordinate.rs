use ckb_testtool::{
    ckb_types::packed::{CellInput, CellOutput, OutPoint},
    ckb_types::{
        core::{TransactionBuilder, TransactionView},
        packed::Script,
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{
    perun_types::ChannelWitnessUnion,
    perun_types::{ChannelStatus, Coordinate, VirtualChannelStatus},
    redeemer,
};

use crate::perun::{self, harness, test::transaction::common::channel_witness};

use super::common::create_cells;

#[derive(Debug, Clone)]
pub struct CoordinateArgs {
    /// The channel cell which tracks the channel on-chain.
    pub channel_cell: OutPoint,
    /// The output channel status (coordinated flag set, canonical state).
    pub state: ChannelStatus,
    /// The DER encoded participant signatures on the canonical state, in party order.
    pub sigs: [Vec<u8>; 2],
    /// The DER encoded coordinator signature on the canonical state.
    pub coord_sig: Vec<u8>,
    /// The Perun channel type script used for the current channel.
    pub pcts_script: Script,
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct CoordinateResult {
    pub tx: TransactionView,
    pub channel_cell: OutPoint,
}

impl Default for CoordinateResult {
    fn default() -> Self {
        CoordinateResult {
            tx: TransactionBuilder::default().build(),
            channel_cell: OutPoint::default(),
        }
    }
}

pub fn mk_coordinate(
    ctx: &mut Context,
    env: &harness::Env,
    args: CoordinateArgs,
) -> Result<CoordinateResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.party_index);
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(payment_input)
            .build(),
    ];

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];

    let pcls_script = env.build_pcls(ctx, Default::default());
    let capacity_for_cs = env.min_capacity_for_channel(args.state.clone())?;
    let channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(pcls_script.clone())
        .type_(Some(args.pcts_script.clone()).pack())
        .build();
    let outputs = vec![(channel_cell.clone(), args.state.as_bytes())];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    // The coordinator certifies the canonical state, which is the state carried in
    // the output status. The Coordinate witness bundles the participant signatures
    // and the coordinator signature over that same state.
    let coordinate = Coordinate::new_builder()
        .state(args.state.state())
        .sig_a(args.sigs[0].pack())
        .sig_b(args.sigs[1].pack())
        .coord_sig(args.coord_sig.pack())
        .build();
    let coordinate_action = redeemer!(ChannelWitnessUnion::Coordinate(coordinate));
    let witness_args = channel_witness!(coordinate_action);

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(headers)
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(CoordinateResult {
        channel_cell: OutPoint::new(tx.hash(), 0),
        tx,
    })
}

/// VCCoordinateArgs describes a recursive coordinate transaction that moves a
/// parent ledger channel and its virtual channel into the coordinated phase
/// together, mirroring Ethereum's `coordinateRecursive`. The parent ledger
/// channel cell carries a `Coordinate` witness (input 0) and the virtual
/// channel cell carries its own `Coordinate` witness (input 1); both cells
/// continue on-chain with `coordinated` set to true.
#[derive(Debug, Clone)]
pub struct VCCoordinateArgs {
    /// The parent ledger channel cell.
    pub channel_cell: OutPoint,
    /// The virtual channel cell shared with the parent.
    pub vc_cell: OutPoint,
    /// The output ledger channel status (coordinated flag set).
    pub lc_status: ChannelStatus,
    /// The output virtual channel status (coordinated flag set).
    pub vc_status: VirtualChannelStatus,
    /// Participant signatures on the canonical ledger channel state, party order.
    pub lc_sigs: [Vec<u8>; 2],
    /// Coordinator signature on the canonical ledger channel state.
    pub lc_coord_sig: Vec<u8>,
    /// Participant signatures on the canonical virtual channel state, party order.
    pub vc_sigs: [Vec<u8>; 2],
    /// Coordinator signature on the canonical virtual channel state.
    pub vc_coord_sig: Vec<u8>,
    /// The Perun channel type script for the parent ledger channel.
    pub pcts_script: Script,
    /// The Perun virtual channel type script.
    pub vcts_script: Script,
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct VCCoordinateResult {
    pub tx: TransactionView,
    pub channel_cell: OutPoint,
    pub vc_cell: OutPoint,
}

impl Default for VCCoordinateResult {
    fn default() -> Self {
        VCCoordinateResult {
            tx: TransactionBuilder::default().build(),
            channel_cell: OutPoint::default(),
            vc_cell: OutPoint::default(),
        }
    }
}

pub fn mk_vc_coordinate(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCCoordinateArgs,
) -> Result<VCCoordinateResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.party_index);
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(args.vc_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(payment_input)
            .build(),
    ];

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
        env.vcts_script_dep.clone(),
        env.vcls_script_dep.clone(),
    ];

    let pcls_script = env.build_pcls(ctx, Default::default());
    let capacity_for_cs = env.min_capacity_for_channel(args.lc_status.clone())?;
    let channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(pcls_script.clone())
        .type_(Some(args.pcts_script.clone()).pack())
        .build();

    let vcls_script = env.build_vcls(ctx, Default::default());
    let capacity_for_vc = env.min_capacity_for_vc_channel(args.vc_status.clone())?;
    let vc_cell = CellOutput::new_builder()
        .capacity(capacity_for_vc.pack())
        .lock(vcls_script.clone())
        .type_(Some(args.vcts_script.clone()).pack())
        .build();

    let outputs = vec![
        (channel_cell.clone(), args.lc_status.as_bytes()),
        (vc_cell.clone(), args.vc_status.as_bytes()),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    // The parent ledger channel's Coordinate witness certifies the canonical LC
    // state; the virtual channel's Coordinate witness certifies the canonical VC
    // state. Witnesses are positional: witness[0] is read for the LC input,
    // witness[1] for the VC input.
    let lc_coordinate = Coordinate::new_builder()
        .state(args.lc_status.state())
        .sig_a(args.lc_sigs[0].pack())
        .sig_b(args.lc_sigs[1].pack())
        .coord_sig(args.lc_coord_sig.pack())
        .build();
    let lc_witness = channel_witness!(redeemer!(ChannelWitnessUnion::Coordinate(lc_coordinate)));

    let vc_coordinate = Coordinate::new_builder()
        .state(args.vc_status.vcstate())
        .sig_a(args.vc_sigs[0].pack())
        .sig_b(args.vc_sigs[1].pack())
        .coord_sig(args.vc_coord_sig.pack())
        .build();
    let vc_witness = channel_witness!(redeemer!(ChannelWitnessUnion::Coordinate(vc_coordinate)));

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(headers)
        .witnesses(vec![
            lc_witness.as_bytes().pack(),
            vc_witness.as_bytes().pack(),
        ])
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(VCCoordinateResult {
        channel_cell: OutPoint::new(tx.hash(), 0),
        vc_cell: OutPoint::new(tx.hash(), 1),
        tx,
    })
}
