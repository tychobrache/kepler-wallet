// Copyright 2019 The Kepler Developers
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

//! Test wallet command line works as expected
#[cfg(test)]
mod wallet_tests {
	use clap;
	use kepler_wallet_util::kepler_util as util;

	use kepler_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

	use clap::{App, ArgMatches};
	use std::path::PathBuf;
	use std::sync::Arc;
	use std::thread;
	use std::time::Duration;
	use std::{env, fs};
	use util::{Mutex, ZeroingString};

	use kepler_wallet_config::{GlobalWalletConfig, WalletConfig, KEPLER_WALLET_DIR};
	use kepler_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use kepler_wallet_libwallet::WalletInst;
	use kepler_wallet_util::kepler_core::global::{self, ChainTypes};
	use kepler_wallet_util::kepler_keychain::ExtKeychain;
	use util::secp::key::SecretKey;

	use super::super::wallet_args;

	fn clean_output_dir(test_dir: &str) {
		let _ = fs::remove_dir_all(test_dir);
	}

	fn setup(test_dir: &str) {
		util::init_test_logger();
		clean_output_dir(test_dir);
		global::set_mining_mode(ChainTypes::AutomatedTesting);
	}

	/// Create a wallet config file in the given current directory
	pub fn config_command_wallet(
		dir_name: &str,
		wallet_name: &str,
	) -> Result<(), kepler_wallet_controller::Error> {
		let mut current_dir;
		let mut default_config = GlobalWalletConfig::default();
		current_dir = env::current_dir().unwrap_or_else(|e| {
			panic!("Error creating config file: {}", e);
		});
		current_dir.push(dir_name);
		current_dir.push(wallet_name);
		let _ = fs::create_dir_all(current_dir.clone());
		let mut config_file_name = current_dir.clone();
		config_file_name.push("kepler-wallet.toml");
		if config_file_name.exists() {
			return Err(kepler_wallet_controller::ErrorKind::ArgumentError(
				"kepler-wallet.toml already exists in the target directory. Please remove it first"
					.to_owned(),
			))?;
		}
		default_config.update_paths(&current_dir);
		default_config
			.write_to_file(config_file_name.to_str().unwrap())
			.unwrap_or_else(|e| {
				panic!("Error creating config file: {}", e);
			});

		println!(
			"File {} configured and created",
			config_file_name.to_str().unwrap(),
		);
		Ok(())
	}

	/// Handles setup and detection of paths for wallet
	pub fn initial_setup_wallet(dir_name: &str, wallet_name: &str) -> WalletConfig {
		let mut current_dir;
		current_dir = env::current_dir().unwrap_or_else(|e| {
			panic!("Error creating config file: {}", e);
		});
		current_dir.push(dir_name);
		current_dir.push(wallet_name);
		let _ = fs::create_dir_all(current_dir.clone());
		let mut config_file_name = current_dir.clone();
		config_file_name.push("kepler-wallet.toml");
		GlobalWalletConfig::new(config_file_name.to_str().unwrap())
			.unwrap()
			.members
			.unwrap()
			.wallet
	}

	fn get_wallet_subcommand<'a>(
		wallet_dir: &str,
		wallet_name: &str,
		args: ArgMatches<'a>,
	) -> ArgMatches<'a> {
		match args.subcommand() {
			("init", Some(init_args)) => {
				// wallet init command should spit out its config file then continue
				// (if desired)
				if init_args.is_present("here") {
					let _ = config_command_wallet(wallet_dir, wallet_name);
				}
				init_args.to_owned()
			}
			_ => ArgMatches::new(),
		}
	}
	//
	// Helper to create an instance of the LMDB wallet
	fn instantiate_wallet(
		mut wallet_config: WalletConfig,
		node_client: LocalWalletClient,
		passphrase: &str,
		account: &str,
	) -> Result<
		(
			Arc<
				Mutex<
					Box<
						WalletInst<
							'static,
							DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
							LocalWalletClient,
							ExtKeychain,
						>,
					>,
				>,
			>,
			Option<SecretKey>,
		),
		kepler_wallet_controller::Error,
	> {
		wallet_config.chain_type = None;
		let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(node_client).unwrap())
			as Box<
				WalletInst<
					DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
		let lc = wallet.lc_provider().unwrap();
		// legacy hack to avoid the need for changes in existing kepler-wallet.toml files
		// remove `wallet_data` from end of path as
		// new lifecycle provider assumes kepler_wallet.toml is in root of data directory
		let mut top_level_wallet_dir = PathBuf::from(wallet_config.clone().data_file_dir);
		if top_level_wallet_dir.ends_with(KEPLER_WALLET_DIR) {
			top_level_wallet_dir.pop();
			wallet_config.data_file_dir = top_level_wallet_dir.to_str().unwrap().into();
		}
		lc.set_wallet_directory(&wallet_config.data_file_dir);
		let keychain_mask = lc
			.open_wallet(None, ZeroingString::from(passphrase), true, false)
			.unwrap();
		let wallet_inst = lc.wallet_inst()?;
		wallet_inst.set_parent_key_id_by_name(account)?;
		Ok((Arc::new(Mutex::new(wallet)), keychain_mask))
	}

	fn execute_command(
		app: &App,
		test_dir: &str,
		wallet_name: &str,
		client: &LocalWalletClient,
		arg_vec: Vec<&str>,
	) -> Result<String, kepler_wallet_controller::Error> {
		let args = app.clone().get_matches_from(arg_vec);
		let _ = get_wallet_subcommand(test_dir, wallet_name, args.clone());
		let mut config = initial_setup_wallet(test_dir, wallet_name);
		//unset chain type so it doesn't get reset
		config.chain_type = None;
		wallet_args::wallet_command(&args, config.clone(), client.clone())
	}

	/// command line tests
	fn command_line_test_impl(test_dir: &str) -> Result<(), kepler_wallet_controller::Error> {
		setup(test_dir);
		// Create a new proxy to simulate server and wallet responses
		let mut wallet_proxy: WalletProxy<
			DefaultLCProvider<LocalWalletClient, ExtKeychain>,
			LocalWalletClient,
			ExtKeychain,
		> = WalletProxy::new(test_dir);
		let chain = wallet_proxy.chain.clone();

		// load app yaml. If it don't exist, just say so and exit
		let yml = load_yaml!("../kepler-wallet.yml");
		let app = App::from_yaml(yml);

		// wallet init
		let arg_vec = vec!["kepler-wallet", "-p", "password", "init", "-h"];
		// should create new wallet file
		let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

		// trying to init twice - should fail
		assert!(execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).is_err());
		let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());

		// add wallet to proxy
		//let wallet1 = test_framework::create_wallet(&format!("{}/wallet1", test_dir), client1.clone());
		let config1 = initial_setup_wallet(test_dir, "wallet1");
		let (wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
		wallet_proxy.add_wallet(
			"wallet1",
			client1.get_send_instance(),
			wallet1.clone(),
			mask1_i.clone(),
		);

		// Create wallet 2
		let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

		let config2 = initial_setup_wallet(test_dir, "wallet2");
		let (wallet2, mask2_i) =
			instantiate_wallet(config2.clone(), client2.clone(), "password", "default")?;
		wallet_proxy.add_wallet(
			"wallet2",
			client2.get_send_instance(),
			wallet2.clone(),
			mask2_i.clone(),
		);

		// Set the wallet proxy listener running
		thread::spawn(move || {
			if let Err(e) = wallet_proxy.run() {
				error!("Wallet Proxy error: {}", e);
			}
		});

		// Create some accounts in wallet 1
		let arg_vec = vec!["kepler-wallet", "-p", "password", "account", "-c", "mining"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"account",
			"-c",
			"account_1",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// Create some accounts in wallet 2
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"account",
			"-c",
			"account_1",
		];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;
		// already exists
		assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"account",
			"-c",
			"account_2",
		];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// let's see those accounts
		let arg_vec = vec!["kepler-wallet", "-p", "password", "account"];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// let's see those accounts
		let arg_vec = vec!["kepler-wallet", "-p", "password", "account"];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// Mine a bit into wallet 1 so we have something to send
		// (TODO: Be able to stop listeners so we can test this better)
		let (wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
		let mask1 = (&mask1_i).as_ref();
		kepler_wallet_controller::controller::owner_single_use(
			wallet1.clone(),
			mask1,
			|api, m| {
				api.set_active_account(m, "mining")?;
				Ok(())
			},
		)?;

		let mut bh = 10u64;
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			mask1,
			bh as usize,
			false,
		);

		let very_long_message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
		                         This part should all be truncated";

		// Update info and check
		let arg_vec = vec!["kepler-wallet", "-p", "password", "-a", "mining", "info"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// try a file exchange
		let file_name = format!("{}/tx1.part_tx", test_dir);
		let response_file_name = format!("{}/tx1.part_tx.response", test_dir);
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"send",
			"-m",
			"file",
			"-d",
			&file_name,
			"-g",
			very_long_message,
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"account_1",
			"receive",
			"-i",
			&file_name,
			"-g",
			"Thanks, Yeast!",
		];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

		// shouldn't be allowed to receive twice
		assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"finalize",
			"-i",
			&response_file_name,
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
		bh += 1;

		let (wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
		let mask1 = (&mask1_i).as_ref();

		// Check our transaction log, should have 10 entries
		kepler_wallet_controller::controller::owner_single_use(
			wallet1.clone(),
			mask1,
			|api, m| {
				api.set_active_account(m, "mining")?;
				let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
				assert!(refreshed);
				assert_eq!(txs.len(), bh as usize);
				Ok(())
			},
		)?;

		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
		bh += 10;

		// update info for each
		let arg_vec = vec!["kepler-wallet", "-p", "password", "-a", "mining", "info"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec!["kepler-wallet", "-p", "password", "-a", "account_1", "info"];
		execute_command(&app, test_dir, "wallet2", &client1, arg_vec)?;

		// check results in wallet 2
		let (wallet2, mask2_i) =
			instantiate_wallet(config2.clone(), client2.clone(), "password", "default")?;
		let mask2 = (&mask2_i).as_ref();

		kepler_wallet_controller::controller::owner_single_use(
			wallet2.clone(),
			mask2,
			|api, m| {
				api.set_active_account(m, "account_1")?;
				let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
				assert_eq!(wallet1_info.last_confirmed_height, bh);
				assert_eq!(wallet1_info.amount_currently_spendable, 10_000_000_000);
				Ok(())
			},
		)?;

		// Self-send to same account, using smallest strategy
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"send",
			"-m",
			"file",
			"-d",
			&file_name,
			"-g",
			"Love, Yeast, Smallest",
			"-s",
			"smallest",
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"receive",
			"-i",
			&file_name,
			"-g",
			"Thanks, Yeast!",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"finalize",
			"-i",
			&response_file_name,
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
		bh += 1;

		// Check our transaction log, should have bh entries + one for the self receive
		let (wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
		let mask1 = (&mask1_i).as_ref();

		kepler_wallet_controller::controller::owner_single_use(
			wallet1.clone(),
			mask1,
			|api, m| {
				api.set_active_account(m, "mining")?;
				let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
				assert!(refreshed);
				assert_eq!(txs.len(), bh as usize + 1);
				Ok(())
			},
		)?;

		// Try using the self-send method, splitting up outputs for the fun of it
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"send",
			"-m",
			"self",
			"-d",
			"mining",
			"-g",
			"Self love",
			"-o",
			"3",
			"-s",
			"smallest",
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
		bh += 1;

		// Check our transaction log, should have bh entries + 2 for the self receives
		let (wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
		let mask1 = (&mask1_i).as_ref();

		kepler_wallet_controller::controller::owner_single_use(
			wallet1.clone(),
			mask1,
			|api, m| {
				api.set_active_account(m, "mining")?;
				let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
				assert!(refreshed);
				assert_eq!(txs.len(), bh as usize + 2);
				Ok(())
			},
		)?;

		// Another file exchange, don't send, but unlock with repair command
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"send",
			"-m",
			"file",
			"-d",
			&file_name,
			"-g",
			"Ain't sending",
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec!["kepler-wallet", "-p", "password", "check", "-d"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// Another file exchange, cancel this time
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"send",
			"-m",
			"file",
			"-d",
			&file_name,
			"-g",
			"Ain't sending 2",
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"cancel",
			"-i",
			"26",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// issue an invoice tx, wallet 2
		let file_name = format!("{}/invoice.slate", test_dir);
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"invoice",
			"-d",
			&file_name,
			"-g",
			"Please give me your precious keplers. Love, Yeast",
			"65",
		];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;
		let output_file_name = format!("{}/invoice.slate.paid", test_dir);

		// now pay the invoice tx, wallet 1
		let arg_vec = vec![
			"kepler-wallet",
			"-a",
			"mining",
			"-p",
			"password",
			"pay",
			"-i",
			&file_name,
			"-d",
			&output_file_name,
			"-g",
			"Here you go",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// and finalize, wallet 2
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"finalize",
			"-i",
			&output_file_name,
		];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// bit more mining
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);
		//bh += 5;

		// txs and outputs (mostly spit out for a visual in test logs)
		let arg_vec = vec!["kepler-wallet", "-p", "password", "-a", "mining", "txs"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// message output (mostly spit out for a visual in test logs)
		let arg_vec = vec![
			"kepler-wallet",
			"-p",
			"password",
			"-a",
			"mining",
			"txs",
			"-i",
			"10",
		];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		// txs and outputs (mostly spit out for a visual in test logs)
		let arg_vec = vec!["kepler-wallet", "-p", "password", "-a", "mining", "outputs"];
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

		let arg_vec = vec!["kepler-wallet", "-p", "password", "txs"];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		let arg_vec = vec!["kepler-wallet", "-p", "password", "outputs"];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// get tx output via -tx parameter
		let mut tx_id = "".to_string();
		kepler_wallet_controller::controller::owner_single_use(
			wallet2.clone(),
			mask2,
			|api, m| {
				api.set_active_account(m, "default")?;
				let (_, txs) = api.retrieve_txs(m, true, None, None)?;
				let some_tx_id = txs[0].tx_slate_id.clone();
				assert!(some_tx_id.is_some());
				tx_id = some_tx_id.unwrap().to_hyphenated().to_string().clone();
				Ok(())
			},
		)?;
		let arg_vec = vec!["kepler-wallet", "-p", "password", "txs", "-t", &tx_id[..]];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

		// let logging finish
		thread::sleep(Duration::from_millis(200));
		Ok(())
	}

	#[test]
	fn wallet_command_line() {
		let test_dir = "target/test_output/command_line";
		if let Err(e) = command_line_test_impl(test_dir) {
			panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
		}
	}
}
