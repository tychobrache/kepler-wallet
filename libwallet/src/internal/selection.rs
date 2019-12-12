// Copyright 2018 The Kepler Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Selection of inputs for building transactions

use crate::error::{Error, ErrorKind};
use crate::internal::keys;
use crate::kepler_core::core::amount_to_hr_string;
use crate::kepler_core::core::asset::Asset;
use crate::kepler_core::core::issued_asset::AssetAction;
use crate::kepler_core::libtx::{
	build,
	proof::{ProofBuild, ProofBuilder},
	tx_fee,
};
use crate::kepler_keychain::{Identifier, Keychain};
use crate::slate::Slate;
use crate::types::*;
use std::collections::HashMap;

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &mut Slate,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: Identifier,
	use_test_nonce: bool,
	mut asset_actions: Vec<AssetAction>,
) -> Result<Context, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut mint_input = 0;
	let mut mint_output = 0;
	for i in &asset_actions {
		match i {
			AssetAction::New { .. } | AssetAction::Issue { .. } => {
				mint_output += 1;
			}
			AssetAction::Withdraw { .. } => {
				mint_input += 1;
			}
			_ => {}
		}
	}

	let (mut elems, inputs, change_amounts_derivations, fee) = select_send_tx(
		wallet,
		slate.amount,
		slate.asset,
		slate.height,
		minimum_confirmations,
		slate.lock_height,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		mint_input,
		mint_output,
	)?;

	let keychain = wallet.keychain();

	while !asset_actions.is_empty() {
		elems.push(build::mint(asset_actions.pop().unwrap()));
	}

	let blinding = slate.add_transaction_elements(keychain, &ProofBuilder::new(keychain), elems)?;

	slate.fee = fee;

	// Create our own private context
	let mut context = Context::new(
		keychain.secp(),
		blinding.secret_key(&keychain.secp()).unwrap(),
		&parent_key_id,
		use_test_nonce,
		0,
	);

	context.fee = fee;

	// Store our private identifiers for each input
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value, input.asset);
	}

	let mut commits: HashMap<Identifier, Option<String>> = HashMap::new();

	// Store change output(s) and cached commits
	for (change_amount, id, mmr_index, asset) in &change_amounts_derivations {
		context.add_output(&id, &mmr_index, *change_amount, asset.clone());
		commits.insert(
			id.clone(),
			wallet.calc_commit_for_cache(*change_amount, &id, asset.clone())?,
		);
	}

	Ok(context)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut output_commits: HashMap<Identifier, (Option<String>, u64)> = HashMap::new();
	// Store cached commits before locking wallet
	for (id, _, change_amount, asset) in &context.get_outputs() {
		output_commits.insert(
			id.clone(),
			(
				wallet.calc_commit_for_cache(*change_amount, &id, asset.clone())?,
				*change_amount,
			),
		);
	}

	let tx_entry = {
		let lock_inputs = context.get_inputs().clone();
		let messages = Some(slate.participant_messages());
		let slate_id = slate.id;
		let height = slate.height;
		let parent_key_id = context.parent_key_id.clone();
		let mut batch = wallet.batch()?;
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, log_id);
		t.tx_slate_id = Some(slate_id.clone());
		let filename = format!("{}.keplertx", slate_id);
		t.stored_tx = Some(filename);
		t.fee = Some(slate.fee);
		let mut amount_debited = 0;
		t.num_inputs = lock_inputs.len();
		for id in lock_inputs {
			let mut coin = batch.get(&id.0, &id.1).unwrap();
			coin.tx_log_entry = Some(log_id);
			amount_debited = amount_debited + coin.value;
			batch.lock_output(&mut coin)?;
		}

		t.amount_debited = amount_debited;
		t.messages = messages;

		// write the output representing our change
		for (id, _, _, asset) in &context.get_outputs() {
			t.num_outputs += 1;
			let (commit, change_amount) = output_commits.get(&id).unwrap().clone();
			t.amount_credited += change_amount;
			batch.save(OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: id.clone(),
				n_child: id.to_path().last_path_index(),
				commit: commit,
				asset: asset.clone(),
				mmr_index: None,
				value: change_amount.clone(),
				status: OutputStatus::Unconfirmed,
				height: height,
				lock_height: 0,
				is_coinbase: false,
				tx_log_entry: Some(log_id),
			})?;
		}
		batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
		batch.commit()?;
		t
	};
	wallet.store_tx(&format!("{}", tx_entry.tx_slate_id.unwrap()), &slate.tx)?;
	Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
pub fn build_recipient_output<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &mut Slate,
	parent_key_id: Identifier,
	use_test_rng: bool,
) -> Result<(Identifier, Context), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// TODO Mint Output. use AssetAction

	// Create a potential output for this transaction
	let key_id = keys::next_available_key(wallet).unwrap();
	let keychain = wallet.keychain().clone();
	let key_id_inner = key_id.clone();
	let amount = slate.amount;
	let height = slate.height;
	let asset = slate.asset;

	let mut out_vec = vec![];
	let mut out_info = vec![];
	out_vec.push(build::output(asset, amount, key_id.clone()));
	out_info.push((asset, amount));
	for mint in slate.tx.assets() {
		out_vec.push(build::output(mint.asset(), mint.amount(), key_id.clone()));
		out_info.push((mint.asset(), mint.amount()));
	}
	let slate_id = slate.id.clone();
	let blinding =
		slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), out_vec)?;

	// Add blinding sum to our context
	let mut context = Context::new(
		keychain.secp(),
		blinding
			.secret_key(wallet.keychain().clone().secp())
			.unwrap(),
		&parent_key_id,
		use_test_rng,
		1,
	);

	context.add_output(&key_id, &None, amount, asset);

	let messages = Some(slate.participant_messages());

	for out in out_info {
		let (asset, amount) = (out.0, out.1);
		let commit = wallet.calc_commit_for_cache(amount, &key_id_inner, asset)?;
		let mut batch = wallet.batch()?;
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);
		t.tx_slate_id = Some(slate_id);
		t.amount_credited = amount;
		t.num_outputs = 1;
		t.messages = messages.clone();
		batch.save(OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: key_id_inner.clone(),
			mmr_index: None,
			n_child: key_id_inner.to_path().last_path_index(),
			commit: commit,
			asset: asset,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(log_id),
		})?;
		batch.save_tx_log_entry(t, &parent_key_id)?;

		batch.commit()?;
	}

	Ok((key_id, context))
}

/// Builds a transaction to send to someone from the HD seed associated with the
/// wallet and the amount to send. Handles reading through the wallet data file,
/// selecting outputs to spend and building the change.
pub fn select_send_tx<T: ?Sized, C, K, B>(
	wallet: &mut T,
	amount: u64,
	asset: Asset,
	current_height: u64,
	minimum_confirmations: u64,
	lock_height: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	mint_input: usize,
	mint_output: usize,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<OutputData>,
		Vec<(u64, Identifier, Option<u64>, Asset)>, // change amounts and derivations
		u64,                                        // fee
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
	B: ProofBuild,
{
	let (coins, _total, main_coins, _main_total, amount, fee) = select_coins_and_fee(
		wallet,
		asset,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		mint_input,
		mint_output,
	)?;

	let (mut parts, change_amounts_derivations) = if main_coins.len() > 0 {
		// build transaction skeleton with inputs and change
		let (mut parts, mut change_amounts_derivations) =
			inputs_and_change(&coins, wallet, amount, 0, change_outputs, asset)?;

		// build transaction skeleton with inputs and change
		let (mut main_parts, mut main_change_amounts_derivations) = inputs_and_change(
			&main_coins,
			wallet,
			0,
			fee,
			1,
			Asset::default(),
		)?;

		parts.append(&mut main_parts);
		change_amounts_derivations.append(&mut main_change_amounts_derivations);
		(parts, change_amounts_derivations)
	} else {
		// build transaction skeleton with inputs and change
		inputs_and_change(&coins, wallet, amount, fee, change_outputs, asset)?
	};

	// This is more proof of concept than anything but here we set lock_height
	// on tx being sent (based on current chain height via api).
	parts.push(build::with_lock_height(lock_height));

	Ok((parts, coins, change_amounts_derivations, fee))
}

/// Select outputs and calculating fee.
pub fn select_coins_and_fee<T: ?Sized, C, K>(
	wallet: &mut T,
	asset: Asset,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	pre_max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	mint_input: usize,
	mint_output: usize,
) -> Result<
	(
		Vec<OutputData>,
		u64,             // total
		Vec<OutputData>, //main_coins for asset
		u64,             // main_total for asset
		u64,             // amount
		u64,             // fee
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// select some spendable coins from the wallet
	let (max_outputs, mut coins) = select_coins(
		wallet,
		asset,
		amount,
		current_height,
		minimum_confirmations,
		pre_max_outputs,
		selection_strategy_is_use_all,
		parent_key_id,
	);

	if asset == Asset::default() {
		// sender is responsible for setting the fee on the partial tx
		// recipient should double check the fee calculation and not blindly trust the
		// sender

		// TODO - Is it safe to spend without a change output? (1 input -> 1 output)
		// TODO - Does this not potentially reveal the senders private key?
		//
		// First attempt to spend without change
		let mut fee = tx_fee(coins.len() + mint_input, 1 + mint_output, 1, None);
		let mut total: u64 = coins.iter().map(|c| c.value).sum();
		let mut amount_with_fee = amount + fee;

		if total == 0 {
			return Err(ErrorKind::NotEnoughFunds {
				available: 0,
				available_disp: amount_to_hr_string(0, false),
				needed: amount_with_fee as u64,
				needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
			})?;
		}

		// The amount with fee is more than the total values of our max outputs
		if total < amount_with_fee && coins.len() == max_outputs {
			return Err(ErrorKind::NotEnoughFunds {
				available: total,
				available_disp: amount_to_hr_string(total, false),
				needed: amount_with_fee as u64,
				needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
			})?;
		}

		let num_outputs = change_outputs + 1 + mint_output;

		// We need to add a change address or amount with fee is more than total
		if total != amount_with_fee {
			fee = tx_fee(coins.len(), num_outputs, 1, None);
			amount_with_fee = amount + fee;

			// Here check if we have enough outputs for the amount including fee otherwise
			// look for other outputs and check again
			while total < amount_with_fee {
				// End the loop if we have selected all the outputs and still not enough funds
				if coins.len() == max_outputs {
					return Err(ErrorKind::NotEnoughFunds {
						available: total as u64,
						available_disp: amount_to_hr_string(total, false),
						needed: amount_with_fee as u64,
						needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
					})?;
				}

				// select some spendable coins from the wallet
				coins = select_coins(
					wallet,
					Asset::default(),
					amount_with_fee,
					current_height,
					minimum_confirmations,
					max_outputs,
					selection_strategy_is_use_all,
					parent_key_id,
				)
				.1;
				fee = tx_fee(coins.len(), num_outputs, 1, None);
				total = coins.iter().map(|c| c.value).sum();
				amount_with_fee = amount + fee;
			}
		}
		Ok((coins, total, vec![], 0, amount, fee))
	} else {
		let mut fee = tx_fee(coins.len() + mint_input, 1 + mint_output, 1, None);
		// select some spendable coins from the wallet
		let (main_max_outputs, mut main_coins) = select_coins(
			wallet,
			Asset::default(),
			fee,
			current_height,
			minimum_confirmations,
			pre_max_outputs,
			selection_strategy_is_use_all,
			parent_key_id,
		);

		fee = tx_fee(
			main_coins.len() + coins.len() + mint_input,
			1 + mint_output,
			1,
			None,
		);
		let mut total: u64 = coins.iter().map(|c| c.value).sum();
		let mut main_total: u64 = coins.iter().map(|c| c.value).sum();
		let mut amount_with_fee = 0 + fee;

		if total < amount || main_total < amount_with_fee {
			return Err(ErrorKind::NotEnoughFunds {
				available: 0,
				available_disp: amount_to_hr_string(0, false),
				needed: amount_with_fee as u64,
				needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
			})?;
		}

		// n change outputs (in asset), and 1 change output for the main coin
		let num_outputs = change_outputs + 1 + mint_output;

		// We need to add a change address or amount with fee is more than total
		if total != amount {
			// Here check if we have enough outputs for the amount including fee otherwise
			// look for other outputs and check again
			while total < amount {
				// End the loop if we have selected all the outputs and still not enough funds
				if coins.len() == max_outputs {
					return Err(ErrorKind::NotEnoughFunds {
						available: total as u64,
						available_disp: amount_to_hr_string(total, false),
						needed: amount as u64,
						needed_disp: amount_to_hr_string(amount as u64, false),
					})?;
				}

				// select some spendable coins from the wallet
				coins = select_coins(
					wallet,
					asset,
					amount,
					current_height,
					minimum_confirmations,
					max_outputs,
					selection_strategy_is_use_all,
					parent_key_id,
				)
				.1;
			}
		}

		// We need to add a change address or amount with fee is more than total
		if main_total != amount_with_fee {
			fee = tx_fee(coins.len() + main_coins.len(), num_outputs, 1, None);
			amount_with_fee = 0 + fee;

			// Here check if we have enough outputs for the amount including fee otherwise
			// look for other outputs and check again
			while main_total < amount_with_fee {
				// End the loop if we have selected all the outputs and still not enough funds
				if main_coins.len() == main_max_outputs {
					return Err(ErrorKind::NotEnoughFunds {
						available: main_total as u64,
						available_disp: amount_to_hr_string(main_total, false),
						needed: amount_with_fee as u64,
						needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
					})?;
				}

				// select some spendable coins from the wallet
				main_coins = select_coins(
					wallet,
					Asset::default(),
					amount_with_fee,
					current_height,
					minimum_confirmations,
					max_outputs,
					selection_strategy_is_use_all,
					parent_key_id,
				)
				.1;
			}
		}

		fee = tx_fee(coins.len() + main_coins.len(), num_outputs, 1, None);
		total = coins.iter().map(|c| c.value).sum();
		main_total = main_coins.iter().map(|c| c.value).sum();
		Ok((coins, total, main_coins, main_total, amount, fee))
	}
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<T: ?Sized, C, K, B>(
	coins: &Vec<OutputData>,
	wallet: &mut T,
	amount: u64,
	fee: u64,
	num_change_outputs: usize,
	asset: Asset,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<(u64, Identifier, Option<u64>, Asset)>,
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
	B: ProofBuild,
{
	let mut parts = vec![];

	// calculate the total across all inputs, and how much is left
	let total: u64 = coins.iter().map(|c| c.value).sum();

	// Fee is only payable with native asset
	if asset == Asset::default() {
		parts.push(build::with_fee(fee));
	}

	// if we are spending 10,000 coins to send 1,000 then our change will be 9,000
	// if the fee is 80 then the recipient will receive 1000 and our change will be
	// 8,920
	let change = total - amount - fee;

	// build inputs using the appropriate derived key_ids
	for coin in coins {
		if coin.is_coinbase {
			parts.push(build::coinbase_input(coin.value, coin.key_id.clone()));
		} else {
			parts.push(build::input(asset, coin.value, coin.key_id.clone()));
		}
	}

	let mut change_amounts_derivations = vec![];

	if change == 0 {
		debug!("No change (sending exactly amount + fee), no change outputs to build");
	} else {
		debug!(
			"Building change outputs: total change: {} ({} outputs)",
			change, num_change_outputs
		);

		let part_change = change / num_change_outputs as u64;
		let remainder_change = change % part_change;

		for x in 0..num_change_outputs {
			// n-1 equal change_outputs and a final one accounting for any remainder
			let change_amount = if x == (num_change_outputs - 1) {
				part_change + remainder_change
			} else {
				part_change
			};

			let change_key = wallet.next_child().unwrap();

			change_amounts_derivations.push((change_amount, change_key.clone(), None, asset));
			parts.push(build::output(asset, change_amount, change_key));
		}
	}

	Ok((parts, change_amounts_derivations))
}

/// Select spendable coins from a wallet.
/// Default strategy is to spend the maximum number of outputs (up to
/// max_outputs). Alternative strategy is to spend smallest outputs first
/// but only as many as necessary. When we introduce additional strategies
/// we should pass something other than a bool in.
/// TODO: Possibly move this into another trait to be owned by a wallet?

pub fn select_coins<T: ?Sized, C, K>(
	wallet: &mut T,
	asset: Asset,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	select_all: bool,
	parent_key_id: &Identifier,
) -> (usize, Vec<OutputData>)
//    max_outputs_available, Outputs
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// first find all eligible outputs based on number of confirmations
	let mut eligible = wallet
		.iter()
		.filter(|out| {
			out.root_key_id == *parent_key_id
				&& out.asset == asset
				&& out.eligible_to_spend(current_height, minimum_confirmations)
		})
		.collect::<Vec<OutputData>>();

	let max_available = eligible.len();

	// sort eligible outputs by increasing value
	eligible.sort_by_key(|out| out.value);

	// use a sliding window to identify potential sets of possible outputs to spend
	// Case of amount > total amount of max_outputs(500):
	// The limit exists because by default, we always select as many inputs as
	// possible in a transaction, to reduce both the Output set and the fees.
	// But that only makes sense up to a point, hence the limit to avoid being too
	// greedy. But if max_outputs(500) is actually not enough to cover the whole
	// amount, the wallet should allow going over it to satisfy what the user
	// wants to send. So the wallet considers max_outputs more of a soft limit.
	if eligible.len() > max_outputs {
		for window in eligible.windows(max_outputs) {
			let windowed_eligibles = window.iter().cloned().collect::<Vec<_>>();
			if let Some(outputs) = select_from(amount, select_all, windowed_eligibles) {
				return (max_available, outputs);
			}
		}
		// Not exist in any window of which total amount >= amount.
		// Then take coins from the smallest one up to the total amount of selected
		// coins = the amount.
		if let Some(outputs) = select_from(amount, false, eligible.clone()) {
			debug!(
				"Extending maximum number of outputs. {} outputs selected.",
				outputs.len()
			);
			return (max_available, outputs);
		}
	} else {
		if let Some(outputs) = select_from(amount, select_all, eligible.clone()) {
			return (max_available, outputs);
		}
	}

	// we failed to find a suitable set of outputs to spend,
	// so return the largest amount we can so we can provide guidance on what is
	// possible
	eligible.reverse();
	(
		max_available,
		eligible.iter().take(max_outputs).cloned().collect(),
	)
}

fn select_from(amount: u64, select_all: bool, outputs: Vec<OutputData>) -> Option<Vec<OutputData>> {
	let total = outputs.iter().fold(0, |acc, x| acc + x.value);
	if total >= amount {
		if select_all {
			return Some(outputs.iter().cloned().collect());
		} else {
			let mut selected_amount = 0;
			return Some(
				outputs
					.iter()
					.take_while(|out| {
						let res = selected_amount < amount;
						selected_amount += out.value;
						res
					})
					.cloned()
					.collect(),
			);
		}
	} else {
		None
	}
}
