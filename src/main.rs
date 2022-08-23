use chrono::prelude::*;
use clap::{arg, Arg, Command};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use web3::contract::{Contract, Options};
use web3::helpers as w3h;
use web3::types::{BlockId, BlockNumber, TransactionId, H160, U256, U64};

fn wei_to_eth(wei_val: U256) -> f64 {
    let res = wei_val.as_u128() as f64;
    let res = res / 1_000_000_000_000_000_000.0;
    res
}

#[tokio::main]
async fn main() -> web3::Result<()> {
    let matches = Command::new("Data Collector")
        .version("1.0")
        .author("Tricster <mediosrity@gmail.com>")
        .about("Web3 Data Collector")
        .subcommand(
            Command::new("get_balance")
                .about("Get balance of a account")
                .arg(arg!(<account> "Account address")),
        )
        .subcommand(
            Command::new("get_transactions")
                .about("Get transactions of a block")
                .arg(Arg::new("block_id").required(true).help("Block ID")),
        )
        .get_matches();
    // arg!(<block_id> "Block ID"),
    dotenv::dotenv().ok();

    if let Some(matches) = matches.subcommand_matches("get_balance") {
        if let Some(account) = matches.get_one::<String>("account") {
            let websocket =
                web3::transports::WebSocket::new(&env::var("QUICK_NODE").unwrap()).await?;
            let web3s = web3::Web3::new(websocket);

            let mut accounts = web3s.eth().accounts().await?;
            accounts.push(H160::from_str(account.as_str()).unwrap());
            println!("Accounts: {:?}", accounts);

            let wei_conv: U256 = U256::exp10(18);
            for account in accounts {
                let balance = web3s.eth().balance(account, None).await?;
                println!(
                    "Eth balance of {:?}: {}",
                    account,
                    balance.checked_div(wei_conv).unwrap()
                );
            }
        } else {
            println!("please provide an account address");
        }
    }

    if let Some(matches) = matches.subcommand_matches("get_transactions") {
        if let Some(block_id) = matches.get_one::<String>("block_id") {
            let file = File::open("src/signatures.json").unwrap();
            let reader = BufReader::new(file);
            let code_sig_lookup: BTreeMap<String, Vec<String>> =
                serde_json::from_reader(reader).unwrap();

            let websocket = web3::transports::WebSocket::new(&env::var("QUICK_NODE").unwrap())
                .await
                .unwrap();
            let web3s = web3::Web3::new(websocket);
            let block = web3s
                .eth()
                .block(BlockId::Number(BlockNumber::Number(U64::from(
                    block_id.parse::<u64>().expect("cast error"),
                ))))
                .await
                .unwrap()
                .unwrap();

            let timestamp = block.timestamp.as_u64() as i64;
            let naive = NaiveDateTime::from_timestamp(timestamp, 0);
            let utc_dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);

            println!(
                "[{}] block id {}, \nparent {}, \ntransactions: {}, \ngas used {}, \ngas limit {}, \nbase fee {}, \ndifficulty {}, \ntotal difficulty {}",
                utc_dt.format("%Y-%m-%d %H:%M:%S"),
                block.number.unwrap(),
                block.parent_hash,
                block.transactions.len(),
                block.gas_used,
                block.gas_limit,
                block.base_fee_per_gas.unwrap(),
                block.difficulty,
                block.total_difficulty.unwrap()
            );

            for transaction_hash in block.transactions {
                let tx = match web3s
                    .eth()
                    .transaction(TransactionId::Hash(transaction_hash))
                    .await
                {
                    Ok(Some(tx)) => tx,
                    _ => {
                        println!("An error occurred.");
                        continue;
                    }
                };
                let index = tx.transaction_index.unwrap_or(U64::from(0 as i32));

                let smart_contract_addr = match tx.to {
                    Some(addr) => match web3s.eth().code(addr, None).await {
                        Ok(code) => {
                            if code == web3::types::Bytes::from([]) {
                                println!("[{index}] Empty code, skipping.");
                                continue;
                            } else {
                                addr
                            }
                        }
                        _ => {
                            println!("Unable to retrieve code, skipping.");
                            continue;
                        }
                    },
                    _ => {
                        println!("[{index}] To address is not a valid address, skipping.");
                        continue;
                    }
                };

                let smart_contract = match Contract::from_json(
                    web3s.eth(),
                    smart_contract_addr,
                    include_bytes!("erc20_abi.json"),
                ) {
                    Ok(contract) => contract,
                    _ => {
                        println!("[{index}] Failed to init contract, skipping.");
                        continue;
                    }
                };

                let token_name: String = match smart_contract
                    .query("name", (), None, Options::default(), None)
                    .await
                {
                    Ok(result) => result,
                    _ => {
                        println!("[{index}] Could not get name, skipping.");
                        continue;
                    }
                };

                let input_str: String = w3h::to_string(&tx.input);
                if input_str.len() < 12 {
                    continue;
                }
                let func_code = input_str[3..11].to_string();
                let func_signature: String = match code_sig_lookup.get(&func_code) {
                    Some(func_sig) => format!("{:?}", func_sig),
                    _ => {
                        println!("Function not found.");
                        "[unknown]".to_string()
                    }
                };

                let from_addr = tx.from.unwrap_or(H160::zero());
                let to_addr = tx.to.unwrap_or(H160::zero());

                let eth_value = wei_to_eth(tx.value);
                println!(
                    "[{}] ({} -> {}) from {}, to {}, value {}, gas {}, gas price {:?}",
                    index,
                    &token_name,
                    &func_signature,
                    w3h::to_string(&from_addr),
                    w3h::to_string(&to_addr),
                    eth_value,
                    tx.gas,
                    tx.gas_price,
                );
            }
        } else {
            println!("please provide a block id");
        }
    }
    Ok(())
}
