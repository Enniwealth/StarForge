use crate::utils::{config, crypto, hardware_wallet, horizon, multisig, print as p};
use anyhow::Result;
use chrono::Utc;
use clap::Subcommand;
use colored::*;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new keypair and save it locally
    Create {
        /// A friendly name for the wallet (e.g. "alice", "deployer")
        name: String,
        /// Fund the wallet via Friendbot immediately (testnet only)
        #[arg(long, default_value = "false")]
        fund: bool,
        /// Network to associate with this wallet (overrides global config)
        #[arg(long, value_parser = ["testnet", "mainnet"])]
        network: Option<String>,
        /// Encrypt the secret key with a passphrase at rest
        #[arg(long, default_value = "false")]
        encrypt: bool,
    },
    /// List all saved wallets
    List,
    /// Show details of a saved wallet including live balance
    Show {
        /// Wallet name
        name: String,
        /// Reveal the secret key in plaintext
        #[arg(long, default_value = "false")]
        reveal: bool,
    },
    /// Fund a wallet via Friendbot (testnet only)
    Fund {
        /// Wallet name to fund
        name: String,
    },
    /// Remove a wallet from local storage
    Remove {
        /// Wallet name to remove
        name: String,
    },
    /// Rename a wallet
    Rename {
        old_name: String,
        new_name: String,
    },

    /// Connect to a hardware wallet (Ledger/Trezor)
    Connect {
        #[arg(value_enum)]
        device: hardware_wallet::HardwareWalletKind,
    },

    /// Sign an arbitrary message using a local or hardware-backed key
    Sign {
        /// Wallet name to use (for local signing)
        name: String,
        /// Message to sign (utf-8)
        message: String,
        /// Use a hardware wallet instead of a local secret key
        #[arg(long, value_enum)]
        hardware: Option<hardware_wallet::HardwareWalletKind>,
    },
    /// Multi-signature account management
    #[command(subcommand)]
    Multisig(MultisigCommands),
}

#[derive(Subcommand)]
pub enum MultisigCommands {
    /// Create a new multi-signature account configuration
    Create {
        /// Name for this multi-sig account
        name: String,
        /// Account ID (public key)
        account_id: String,
        /// Network (testnet or mainnet)
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    /// Add a signer to a multi-sig account
    AddSigner {
        /// Multi-sig account name
        account: String,
        /// Signer public key
        public_key: String,
        /// Signer weight (1-255)
        #[arg(long, default_value = "1")]
        weight: u8,
        /// Optional friendly name for this signer
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a signer from a multi-sig account
    RemoveSigner {
        /// Multi-sig account name
        account: String,
        /// Signer public key to remove
        public_key: String,
    },
    /// Set thresholds for a multi-sig account
    SetThresholds {
        /// Multi-sig account name
        account: String,
        /// Low threshold (for low-security operations)
        #[arg(long)]
        low: Option<u8>,
        /// Medium threshold (for medium-security operations)
        #[arg(long)]
        medium: Option<u8>,
        /// High threshold (for high-security operations like changing signers)
        #[arg(long)]
        high: Option<u8>,
    },
    /// List all multi-sig accounts
    List,
    /// Show details of a multi-sig account
    Show {
        /// Multi-sig account name
        name: String,
    },
}

pub fn handle(cmd: WalletCommands) -> Result<()> {
    match cmd {
        WalletCommands::Create { name, fund, network, encrypt } => create(name, fund, network, encrypt),
        WalletCommands::List                  => list(),
        WalletCommands::Show { name, reveal } => show(name, reveal),
        WalletCommands::Fund { name } => fund_wallet(name),
        WalletCommands::Remove { name } => remove(name),
        WalletCommands::Rename { old_name, new_name } => rename(old_name, new_name),
        WalletCommands::Connect { device } => connect_hardware(device),
        WalletCommands::Sign { name, message, hardware } => sign_message(name, message, hardware),
        WalletCommands::Multisig(cmd) => handle_multisig(cmd),
    }
}

fn connect_hardware(device: hardware_wallet::HardwareWalletKind) -> Result<()> {
    p::header("Hardware Wallet");
    p::step(1, 2, &format!("Connecting to {:?}…", device));
    hardware_wallet::connect(device)?;
    p::step(2, 2, "Device detected");
    println!();
    p::success(&format!("{:?} connected (device detection only).", device));
    Ok(())
}

fn sign_message(
    name: String,
    message: String,
    hardware: Option<hardware_wallet::HardwareWalletKind>,
) -> Result<()> {
    p::header("Sign Message");
    p::kv("Wallet", &name);

    let msg_bytes = message.as_bytes();

    if let Some(kind) = hardware {
        p::kv("Signer", &format!("{:?}", kind));
        let sig = hardware_wallet::sign(kind, msg_bytes)?;
        p::separator();
        p::kv_accent("Message", &message);
        p::kv("Signature (hex)", &hex::encode(sig));
        p::separator();
        return Ok(());
    }

    let cfg = config::load()?;
    let w = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    let sk = w
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' has no local secret key", name))?;

    let plain_sk = if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
        sk.clone()
    } else {
        let pwd = crypto::prompt_password(&format!("Enter password for wallet '{}'", name), false)?;
        crypto::decrypt_secret(&pwd, sk).map_err(|_| anyhow::anyhow!("Incorrect password or unable to decrypt."))?
    };

    let decoded_secret = StellarPrivateKey::from_string(&plain_sk)?;
    let signing_key = SigningKey::from_bytes(&decoded_secret.0);
    let sig = signing_key.sign(msg_bytes);

    p::separator();
    p::kv_accent("Message", &message);
    p::kv("Signature (hex)", &hex::encode(sig.to_bytes()));
    p::separator();
    Ok(())
}

fn generate_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let public_key = StellarPublicKey(verifying_key.to_bytes()).to_string();
    let secret_key = StellarPrivateKey(seed).to_string();

    (public_key, secret_key)
}

fn create(name: String, fund: bool, network_override: Option<String>, encrypt: bool) -> Result<()> {
    let mut cfg = config::load()?;

    config::validate_wallet_name(&name)?;

    if cfg.wallets.iter().any(|w| w.name == name) {
        anyhow::bail!("A wallet named '{}' already exists.", name);
    }

    let network = network_override.unwrap_or_else(|| cfg.network.clone());

    let steps = if fund { 3 } else { 2 };
    p::header(&format!("Creating wallet '{}'", name));

    p::step(1, steps, "Generating keypair…");
    let (public_key, secret_key) = generate_keypair();
    println!();
    p::kv_accent("Public Key", &public_key);

    println!();
    let secret_to_store = if encrypt {
        let pwd = crypto::prompt_password("Set a secure passphrase to encrypt this wallet", true)?;
        crypto::encrypt_secret(&pwd, &secret_key)?
    } else {
        secret_key.clone()
    };

    let status = if encrypt { "Encrypted and safely stored." } else { "Stored in plaintext (not recommended for mainnet)." };
    p::kv("Secret Key", status);
    println!();

    p::step(2, steps, "Saving to ~/.starforge/config.toml…");
    let wallet = config::WalletEntry {
        name: name.clone(),
        public_key: public_key.clone(),
        secret_key: Some(secret_to_store),
        network: network.clone(),
        created_at: Utc::now().to_rfc3339(),
        funded: false,
    };
    cfg.wallets.push(wallet);

    if fund {
        if network == "mainnet" {
            p::warn("Friendbot is not available on Mainnet. Skipping fund step.");
        } else {
            p::step(3, steps, "Funding via Friendbot…");
            match horizon::fund_account(&public_key) {
                Ok(_) => {
                    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == name) {
                        w.funded = true;
                    }
                    p::success("Funded with 10,000 XLM on testnet");
                }
                Err(e) => p::warn(&format!("Funding failed: {}", e)),
            }
        }
    }

    config::save(&cfg)?;
    println!();
    p::success(&format!("Wallet '{}' created and saved!", name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", name).cyan()
    ));
    Ok(())
}

fn list() -> Result<()> {
    let cfg = config::load()?;

    p::header("Saved Wallets");

    if cfg.wallets.is_empty() {
        p::info(&format!(
            "No wallets yet on {}. Run `starforge wallet create <name>` to get started.",
            cfg.network
        ));
        return Ok(());
    }

    p::separator();

    for (i, w) in cfg.wallets.iter().enumerate() {
        let status = if w.funded {
            "funded".green()
        } else {
            "unfunded".dimmed()
        };

        println!("  {:>2}. {} [{}]", i + 1, w.name.bold(), status);
        p::kv("Key", &w.public_key);
        p::kv("Net", &w.network);

        if i < cfg.wallets.len() - 1 {
            println!();
        }
    }

    p::separator();
    p::kv(
        &format!("{} wallet(s)", cfg.wallets.len()),
        &format!("on {} — {}", cfg.network, config::config_path().display()),
    );

    Ok(())
}

fn show(name: String, reveal: bool) -> Result<()> {
    let cfg = config::load()?;
    let w = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    p::header(&format!("Wallet: {}", w.name));
    p::separator();
    p::kv_accent("Public Key", &w.public_key);

    if reveal {
        if let Some(sk) = &w.secret_key {
            // Check if it's plaintext
            if !sk.contains(':') && sk.starts_with('S') && sk.len() == 56 {
                p::warn("Warning: This wallet is using an unencrypted legacy key!");
                p::kv("Secret Key", sk);
            } else {
                let pwd = crypto::prompt_password(&format!("Enter password for wallet '{}'", name), false)?;
                match crypto::decrypt_secret(&pwd, sk) {
                    Ok(plain_sk) => p::kv("Secret Key", &plain_sk),
                    Err(_) => anyhow::bail!("Incorrect password or unable to decrypt."),
                }
            }
        }
    } else {
        p::kv(
            "Secret Key",
            &format!("{} (--reveal to show)", "*".repeat(20)),
        );
    }

    p::kv("Network", &w.network);
    p::kv("Funded", if w.funded { "yes" } else { "no" });
    p::kv("Created", &w.created_at);
    p::separator();

    p::info(&format!("Fetching live balance on {}…", w.network));
    match horizon::fetch_account(&w.public_key, &w.network) {
        Ok(account) => {
            println!();
            for bal in &account.balances {
                let asset = bal.asset_code.as_deref().unwrap_or("XLM");
                p::kv_accent(asset, &format!("{} {}", bal.balance, asset));
            }
        }
        Err(_) => {
            p::warn("Account not yet active on-chain. Fund it with `starforge wallet fund`");
        }
    }
    Ok(())
}

fn fund_wallet(name: String) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let mut cfg = config::load()?;

    if cfg.network == "mainnet" {
        anyhow::bail!("Friendbot is not available on Mainnet.");
    }

    let public_key = cfg
        .wallets
        .iter()
        .find(|w| w.name == name)
        .map(|w| w.public_key.clone())
        .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

    p::info(&format!("Funding '{}' via Friendbot…", name));
    horizon::fund_account(&public_key)?;

    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == name) {
        w.funded = true;
    }
    config::save(&cfg)?;

    println!();
    p::success("Account funded with 10,000 XLM on testnet!");
    p::kv_accent("Public Key", &public_key);
    Ok(())
}

fn remove(name: String) -> Result<()> {
    config::validate_wallet_name(&name)?;
    let mut cfg = config::load()?;
    let before = cfg.wallets.len();
    cfg.wallets.retain(|w| w.name != name);

    if cfg.wallets.len() == before {
        anyhow::bail!("No wallet named '{}' found", name);
    }

    config::save(&cfg)?;
    p::success(&format!("Wallet '{}' removed", name));
    Ok(())
}
fn rename(old_name: String, new_name: String) -> Result<()> {
    config::validate_wallet_name(&old_name)?;
    config::validate_wallet_name(&new_name)?;
    
    let mut cfg = config::load()?;
    if !cfg.wallets.iter().any(|w| w.name == old_name) {
        anyhow::bail!("No wallet named '{}' found", old_name);
    }

    if cfg.wallets.iter().any(|w| w.name == new_name) {
        anyhow::bail!("A wallet named '{}' already exists", new_name);
    }
    if let Some(w) = cfg.wallets.iter_mut().find(|w| w.name == old_name) {
        w.name = new_name.clone();
    }

    config::save(&cfg)?;
    println!();
    p::success(&format!("Wallet renamed: '{}' → '{}'", old_name, new_name));
    p::info(&format!(
        "View it with: {}",
        format!("starforge wallet show {}", new_name).cyan()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generate_keypair;
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use std::collections::HashSet;
    use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey as StellarPublicKey};

    #[test]
    fn generates_valid_unique_stellar_ed25519_keypairs() {
        let mut public_keys = HashSet::new();
        let mut secret_keys = HashSet::new();
        let message = b"starforge wallet keypair validation";

        for _ in 0..1000 {
            let (public_key, secret_key) = generate_keypair();

            assert!(public_key.starts_with('G'));
            assert!(secret_key.starts_with('S'));
            assert!(public_keys.insert(public_key.clone()));
            assert!(secret_keys.insert(secret_key.clone()));

            let decoded_public = StellarPublicKey::from_string(&public_key).unwrap();
            let decoded_secret = StellarPrivateKey::from_string(&secret_key).unwrap();

            assert_eq!(decoded_public.to_string(), public_key);
            assert_eq!(decoded_secret.to_string(), secret_key);

            let signing_key = SigningKey::from_bytes(&decoded_secret.0);
            let verifying_key = VerifyingKey::from_bytes(&decoded_public.0).unwrap();

            assert_eq!(signing_key.verifying_key().to_bytes(), decoded_public.0);

            let signature = signing_key.sign(message);
            verifying_key.verify(message, &signature).unwrap();
        }
    }
}

fn handle_multisig(cmd: MultisigCommands) -> Result<()> {
    match cmd {
        MultisigCommands::Create { name, account_id, network } => {
            multisig_create(name, account_id, network)
        }
        MultisigCommands::AddSigner { account, public_key, weight, name } => {
            multisig_add_signer(account, public_key, weight, name)
        }
        MultisigCommands::RemoveSigner { account, public_key } => {
            multisig_remove_signer(account, public_key)
        }
        MultisigCommands::SetThresholds { account, low, medium, high } => {
            multisig_set_thresholds(account, low, medium, high)
        }
        MultisigCommands::List => multisig_list(),
        MultisigCommands::Show { name } => multisig_show(name),
    }
}

fn multisig_create(name: String, account_id: String, network: String) -> Result<()> {
    config::validate_wallet_name(&name)?;
    config::validate_public_key(&account_id)?;
    config::validate_network(&network)?;

    let mut cfg = config::load()?;

    // Check if multisig account already exists
    if let Some(multisig_accounts) = cfg.wallets.iter().find(|w| w.name == format!("multisig_{}", name)) {
        anyhow::bail!("Multi-sig account '{}' already exists", name);
    }

    p::header(&format!("Creating multi-sig account '{}'", name));

    let multisig_account = multisig::MultiSigAccount {
        name: name.clone(),
        account_id: account_id.clone(),
        signers: vec![],
        thresholds: multisig::Thresholds::default(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    // Store as a special wallet entry
    let wallet = config::WalletEntry {
        name: format!("multisig_{}", name),
        public_key: account_id.clone(),
        secret_key: Some(serde_json::to_string(&multisig_account)?),
        network: network.clone(),
        created_at: multisig_account.created_at.clone(),
        funded: false,
    };

    cfg.wallets.push(wallet);
    config::save(&cfg)?;

    println!();
    p::success(&format!("Multi-sig account '{}' created!", name));
    p::kv_accent("Account ID", &account_id);
    p::kv("Network", &network);
    p::info("Add signers with: starforge wallet multisig add-signer");
    Ok(())
}

fn multisig_add_signer(account: String, public_key: String, weight: u8, signer_name: Option<String>) -> Result<()> {
    config::validate_public_key(&public_key)?;
    multisig::validate_weight(weight)?;

    let mut cfg = config::load()?;
    let wallet_name = format!("multisig_{}", account);

    let wallet = cfg.wallets.iter_mut()
        .find(|w| w.name == wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Multi-sig account '{}' not found", account))?;

    let mut multisig_account: multisig::MultiSigAccount = serde_json::from_str(
        wallet.secret_key.as_ref().unwrap()
    )?;

    // Check if signer already exists
    if multisig_account.signers.iter().any(|s| s.public_key == public_key) {
        anyhow::bail!("Signer '{}' already exists in account '{}'", public_key, account);
    }

    let signer = multisig::Signer {
        public_key: public_key.clone(),
        weight,
        name: signer_name.clone(),
    };

    multisig_account.signers.push(signer);

    // Validate thresholds still make sense
    let total_weight = multisig::calculate_total_weight(&multisig_account.signers);
    multisig::validate_thresholds(&multisig_account.thresholds, total_weight)?;

    wallet.secret_key = Some(serde_json::to_string(&multisig_account)?);
    config::save(&cfg)?;

    println!();
    p::success(&format!("Signer added to multi-sig account '{}'", account));
    p::kv_accent("Public Key", &public_key);
    p::kv("Weight", &weight.to_string());
    if let Some(name) = signer_name {
        p::kv("Name", &name);
    }
    p::kv("Total Weight", &total_weight.to_string());
    Ok(())
}

fn multisig_remove_signer(account: String, public_key: String) -> Result<()> {
    config::validate_public_key(&public_key)?;

    let mut cfg = config::load()?;
    let wallet_name = format!("multisig_{}", account);

    let wallet = cfg.wallets.iter_mut()
        .find(|w| w.name == wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Multi-sig account '{}' not found", account))?;

    let mut multisig_account: multisig::MultiSigAccount = serde_json::from_str(
        wallet.secret_key.as_ref().unwrap()
    )?;

    let before_count = multisig_account.signers.len();
    multisig_account.signers.retain(|s| s.public_key != public_key);

    if multisig_account.signers.len() == before_count {
        anyhow::bail!("Signer '{}' not found in account '{}'", public_key, account);
    }

    // Validate thresholds still make sense
    let total_weight = multisig::calculate_total_weight(&multisig_account.signers);
    if total_weight > 0 {
        multisig::validate_thresholds(&multisig_account.thresholds, total_weight)?;
    }

    wallet.secret_key = Some(serde_json::to_string(&multisig_account)?);
    config::save(&cfg)?;

    println!();
    p::success(&format!("Signer removed from multi-sig account '{}'", account));
    p::kv("Remaining Signers", &multisig_account.signers.len().to_string());
    p::kv("Total Weight", &total_weight.to_string());
    Ok(())
}

fn multisig_set_thresholds(account: String, low: Option<u8>, medium: Option<u8>, high: Option<u8>) -> Result<()> {
    let mut cfg = config::load()?;
    let wallet_name = format!("multisig_{}", account);

    let wallet = cfg.wallets.iter_mut()
        .find(|w| w.name == wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Multi-sig account '{}' not found", account))?;

    let mut multisig_account: multisig::MultiSigAccount = serde_json::from_str(
        wallet.secret_key.as_ref().unwrap()
    )?;

    if let Some(l) = low {
        multisig::validate_threshold(l)?;
        multisig_account.thresholds.low = l;
    }
    if let Some(m) = medium {
        multisig::validate_threshold(m)?;
        multisig_account.thresholds.medium = m;
    }
    if let Some(h) = high {
        multisig::validate_threshold(h)?;
        multisig_account.thresholds.high = h;
    }

    // Validate thresholds
    let total_weight = multisig::calculate_total_weight(&multisig_account.signers);
    multisig::validate_thresholds(&multisig_account.thresholds, total_weight)?;

    wallet.secret_key = Some(serde_json::to_string(&multisig_account)?);
    config::save(&cfg)?;

    println!();
    p::success(&format!("Thresholds updated for multi-sig account '{}'", account));
    p::kv("Low", &multisig_account.thresholds.low.to_string());
    p::kv("Medium", &multisig_account.thresholds.medium.to_string());
    p::kv("High", &multisig_account.thresholds.high.to_string());
    p::kv("Total Weight", &total_weight.to_string());
    Ok(())
}

fn multisig_list() -> Result<()> {
    let cfg = config::load()?;

    p::header("Multi-Signature Accounts");

    let multisig_accounts: Vec<_> = cfg.wallets.iter()
        .filter(|w| w.name.starts_with("multisig_"))
        .collect();

    if multisig_accounts.is_empty() {
        p::info("No multi-sig accounts found. Create one with: starforge wallet multisig create");
        return Ok(());
    }

    p::separator();

    for (i, wallet) in multisig_accounts.iter().enumerate() {
        let multisig_account: multisig::MultiSigAccount = serde_json::from_str(
            wallet.secret_key.as_ref().unwrap()
        )?;

        let display_name = wallet.name.strip_prefix("multisig_").unwrap_or(&wallet.name);
        println!("  {:>2}. {}", i + 1, display_name.bold());
        p::kv("Account ID", &multisig_account.account_id);
        p::kv("Network", &wallet.network);
        p::kv("Signers", &multisig_account.signers.len().to_string());
        p::kv("Total Weight", &multisig::calculate_total_weight(&multisig_account.signers).to_string());

        if i < multisig_accounts.len() - 1 {
            println!();
        }
    }

    p::separator();
    Ok(())
}

fn multisig_show(name: String) -> Result<()> {
    let cfg = config::load()?;
    let wallet_name = format!("multisig_{}", name);

    let wallet = cfg.wallets.iter()
        .find(|w| w.name == wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Multi-sig account '{}' not found", name))?;

    let multisig_account: multisig::MultiSigAccount = serde_json::from_str(
        wallet.secret_key.as_ref().unwrap()
    )?;

    p::header(&format!("Multi-Sig Account: {}", name));
    p::separator();
    p::kv_accent("Account ID", &multisig_account.account_id);
    p::kv("Network", &wallet.network);
    p::kv("Created", &multisig_account.created_at);
    
    println!();
    p::info("Thresholds:");
    p::kv("  Low", &multisig_account.thresholds.low.to_string());
    p::kv("  Medium", &multisig_account.thresholds.medium.to_string());
    p::kv("  High", &multisig_account.thresholds.high.to_string());

    println!();
    p::info(&format!("Signers ({}):", multisig_account.signers.len()));
    
    if multisig_account.signers.is_empty() {
        p::warn("  No signers configured yet");
    } else {
        for (i, signer) in multisig_account.signers.iter().enumerate() {
            println!();
            p::kv(&format!("  [{}] Key", i + 1), &signer.public_key);
            p::kv(&format!("  [{}] Weight", i + 1), &signer.weight.to_string());
            if let Some(ref signer_name) = signer.name {
                p::kv(&format!("  [{}] Name", i + 1), signer_name);
            }
        }
    }

    let total_weight = multisig::calculate_total_weight(&multisig_account.signers);
    println!();
    p::kv_accent("Total Weight", &total_weight.to_string());
    
    p::separator();
    Ok(())
}
