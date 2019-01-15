extern crate rand;
extern crate bitcoin;
extern crate ini;
extern crate jsonrpc;
extern crate secp256k1;
extern crate serde;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate sha2;
extern crate bincode;

use std::env;
use std::process;
use std::str::FromStr;

use bitcoin::util::misc::hex_bytes;
use bitcoin::blockdata::transaction;
use bitcoin::network::serialize::{serialize, deserialize};
use bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Transaction};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::{Privkey};

use secp256k1::{Secp256k1, Message};

use sha2::Sha512;

use rand::rngs::OsRng;

use ed25519_dalek::Keypair as ed25519_Keypair;
use ed25519_dalek::SecretKey as ed25519_SecretKey;
use ed25519_dalek::PublicKey as ed25519_PublicKey;

use curve25519_dalek::edwards::CompressedEdwardsY;

// Borrowed from Andrew Poelstra's rust-bitcoin library
/// An iterator that returns pairs of elements
pub struct Pair<I>
    where I: Iterator
{
    iter: I,
    last_elem: Option<I::Item>
}

impl<I: Iterator> Iterator for Pair<I> {
    type Item = (I::Item, I::Item);

    #[inline]
    fn next(&mut self) -> Option<(I::Item, I::Item)> {
        let elem1 = self.iter.next();
        if elem1.is_none() {
            None
        } else {
            let elem2 = self.iter.next();
            if elem2.is_none() {
                self.last_elem = elem1;
                None
            } else {
                Some((elem1.unwrap(), elem2.unwrap()))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.iter.size_hint() {
            (n, None) => (n/2, None),
            (n, Some(m)) => (n/2, Some(m/2))
        }
    }
}

impl<I: Iterator> Pair<I> {
    /// Returns the last element of the iterator if there were an odd
    /// number of elements remaining before it was Pair-ified.
    #[inline]
    pub fn remainder(self) -> Option<I::Item> {
        self.last_elem
    }
}

/// Returns an iterator that returns elements of the original iterator 2 at a time
pub trait Pairable : Sized + Iterator {
    /// Returns an iterator that returns elements of the original iterator 2 at a time
    fn pair(self) -> Pair<Self>;
}

impl<I: Iterator> Pairable for I {
    /// Creates an iterator that yields pairs of elements from the underlying
    /// iterator, yielding `None` when there are fewer than two elements to
    /// return.
    #[inline]
    fn pair(self) -> Pair<I> {
        Pair {iter: self, last_elem: None }
    }
}

/// Convert a slice of u8 to a hex string
pub fn to_hex(s: &[u8]) -> String {
    let r : Vec<String> = s.to_vec().iter().map(|b| format!("{:02x}", b)).collect();
    return r.join("");
}

// borrowed from Andrew Poelstra's rust-bitcoin library
/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn from_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut v = vec![];
    let mut iter = s.chars().pair();
    // Do the parsing
    iter.by_ref().fold(Ok(()), |e, (f, s)| 
        if e.is_err() { e }
        else {
            match (f.to_digit(16), s.to_digit(16)) {
                (None, _) => Err("unexpected hex digit"),
                (_, None) => Err("unexpected hex digit"),
                (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
            }
        }
    )?;
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err("hexstring of odd length"),
        None => Ok(v)
    }
}


pub fn main() {
    let argv : Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: {} [command] [args...]", argv[0]);
        process::exit(1);
    }

    match argv[1].as_str() {
        "eddsa-privkey" => {
            let mut csprng: OsRng = OsRng::new().unwrap();
            let keypair: ed25519_Keypair = ed25519_Keypair::generate::<Sha512, _>(&mut csprng);

            let privkey_hex = to_hex(&keypair.secret.to_bytes());
            println!("{}", &privkey_hex);
        },
        "eddsa-pubkey" => {
            if argv.len() < 3 {
                eprintln!("Usage: {} eddsa-pubkey EDDSA_PRIVATE_KEY", argv[0]);
                process::exit(1);
            }

            let secret_bytes = from_hex(&argv[2]).unwrap();
            let secret_key = ed25519_SecretKey::from_bytes(&secret_bytes).unwrap();
            let pubkey = ed25519_PublicKey::from_secret::<Sha512>(&secret_key);

            let pubkey_hex = to_hex(&pubkey.to_bytes());
            println!("{}", &pubkey_hex);
        },
        "eddsa-pubkey-check" => {
            if argv.len() < 3 {
                eprintln!("Usage: {} eddsa-pubkey-check EDDSA_PUBLIC_KEY", argv[0]);
                process::exit(1);
            }

            let pubkey_bytes = from_hex(&argv[2]).unwrap();
            let mut pubkey_slice = [0; 32];
            assert!(pubkey_bytes.len() == 32);
            pubkey_slice.copy_from_slice(&pubkey_bytes[..]);

            let compressed_pubkey = CompressedEdwardsY(pubkey_slice);
            let _pubkey = compressed_pubkey.decompress().unwrap();
            
            // if we get here, then it's valid
        },
        "decode-tx" => {
            if argv.len() < 3 {
                eprintln!("Usage: {} decode-tx RAW_TRANSACTION", argv[0]);
                process::exit(1);
            }

            let raw_tx = argv[2].as_str();
            let tx_bytes = hex_bytes(raw_tx).unwrap();
            let tx : transaction::Transaction = deserialize(&tx_bytes).unwrap();

            // TODO: reverse transaction byte order to from be to le
            println!("{:?}", tx);
        },
        "make-tx" => {
            // parse -- first arg is number of inputs
            let usage_str = "Usage: {} make-tx inputs [OUTPOINT_TXID OUTPOINT_INDEX SCRIPT_SIG SEQUENCE...] outputs [VALUE SCRIPTPUBKEY...] [LOCKTIME]";
            if argv.len() < 3 {
                eprintln!("{}", usage_str);
                process::exit(1);
            }

            let argv_index = 3;
            if argv[argv_index-1] != "inputs" {
                eprintln!("{}", usage_str);
                process::exit(1);
            }

            let mut num_inputs = 0;
            let mut num_outputs = 0;

            for i in argv_index..argv.len() {
                if argv[i] == "outputs" {
                    num_inputs = i - argv_index;
                    num_outputs = argv.len() - i - 1;
                    break;
                }
            }

            if num_inputs == 0 || num_outputs == 0 {
                eprintln!("{}", usage_str);
                process::exit(1);
            }

            if num_inputs % 4 != 0 {
                eprintln!("Invalid inputs: must be mod 4 (got {})", num_inputs);
                process::exit(1);
            }

            let locktime =
                if num_outputs % 2 != 0 {
                    num_outputs -= 1;
                    argv[argv.len()-1].parse::<u32>().unwrap()
                }
                else {
                    0
                };

            if num_outputs % 2 != 0 {
                eprintln!("Invalid outputs: must be mod 2 (got {})", num_outputs);
                process::exit(1);
            }

            // number of argument-sets
            num_inputs /= 4;
            num_outputs /= 2;

            let mut inputs : Vec<TxIn> = Vec::with_capacity(num_inputs);
            let mut outputs : Vec<TxOut> = Vec::with_capacity(num_outputs);

            let mut i = argv_index;
            while i < argv.len() && i < argv_index + num_inputs * 4 {
                assert!(i + 3 < argv.len());

                let outpoint_txid_bytes = hex_bytes(&argv[i].as_str()).unwrap();
                let outpoint_index = argv[i+1].parse::<u32>().unwrap();
                let script_sig_bytes = hex_bytes(&argv[i+2].as_str()).unwrap();
                let sequence = argv[i+3].parse::<u32>().unwrap();

                i += 4;

                // reverse the txid -- the bitcoin library treats it as a big-endian value
                let mut outpoint_txid_bytes_be = [0u8; 32];
                for j in 0..32 {
                    outpoint_txid_bytes_be[j] = outpoint_txid_bytes[32 - j - 1];
                }

                let next_input = TxIn {
                    previous_output: OutPoint {
                        txid: Sha256dHash::from(&outpoint_txid_bytes_be[..]),
                        vout: outpoint_index
                    },
                    script_sig: Script::from(script_sig_bytes[..].to_vec()),
                    sequence: sequence,
                    witness: vec![]
                };
                inputs.push(next_input);
            }

            // skip "outputs"
            assert!(argv[i] == "outputs");
            i += 1;

            while i < argv.len() && i < argv_index + num_inputs * 4 + 1 + num_outputs * 2 {
                assert!(i + 1 < argv.len());

                let output_value = argv[i].parse::<u64>().unwrap();
                let output_scriptpubkey_bytes = hex_bytes(&argv[i+1]).unwrap();

                i += 2;

                let next_output = TxOut {
                    value: output_value,
                    script_pubkey: Script::from(output_scriptpubkey_bytes[..].to_vec())
                };
                outputs.push(next_output);
            }

            let tx = Transaction {
                version: 1,
                lock_time: locktime,
                input: inputs,
                output: outputs
            };

            let tx_bytes = serialize(&tx).unwrap();
            println!("{}", to_hex(&tx_bytes[..]));
        },
        "sign-tx" => {
            if argv.len() < 6 {
                eprintln!("Usage: {} sign-tx RAW_TX SCRIPT_PUBKEY KEY_BUNDLE INPUT_INDEX [SIGHASH]", argv[0]);
                process::exit(1);
            }

            let raw_tx = argv[2].as_str();
            let script_pubkey_str = argv[3].as_str();
            let key_bundle = argv[4].as_str();
            let input_index = argv[5].parse::<usize>().unwrap();
            let sighash_u32 = 
                if argv.len() >= 7 {
                    argv[6].parse::<u32>().unwrap()
                }
                else {
                    0x01
                };

            let mut tx : transaction::Transaction = deserialize(&hex_bytes(&raw_tx).unwrap()).unwrap();
            let script_pubkey = Script::from(hex_bytes(&script_pubkey_str).unwrap());
            let h = tx.signature_hash(input_index, &script_pubkey, sighash_u32);

            // TODO: expand to multisig and segwit
            let secp = Secp256k1::new();
            let privkey = Privkey::from_str(key_bundle).unwrap();
            let mut sig = secp.sign(&Message::from_slice(&h.as_bytes()[..]).unwrap(), privkey.secret_key());
            sig.normalize_s(&secp);

            let mut sig_bytes = sig.serialize_der(&secp);
            sig_bytes.push(sighash_u32 as u8);

            // can produce a script-sig 
            let script_sig = Builder::new()
                .push_slice(&sig_bytes[..])
                .push_slice(&privkey.public_key(&secp).serialize())
                .into_script();

            tx.input[input_index].script_sig = script_sig;
            
            let tx_bytes = serialize(&tx).unwrap();
            println!("{}", to_hex(&tx_bytes[..]));
        },
        _ => {
            eprintln!("Unrecognized command '{}'", argv[1]);
            process::exit(1);
        }
    };
}
