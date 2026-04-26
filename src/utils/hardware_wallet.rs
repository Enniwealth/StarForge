use anyhow::Result;
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HardwareWalletKind {
    Ledger,
    Trezor,
}

#[cfg(not(feature = "hardware-wallet"))]
pub fn connect(kind: HardwareWalletKind) -> Result<()> {
    anyhow::bail!(
        "Hardware wallet support is disabled in this build. Rebuild with `--features hardware-wallet` to enable {:?} detection.",
        kind
    )
}

#[cfg(feature = "hardware-wallet")]
pub fn connect(kind: HardwareWalletKind) -> Result<()> {
    // Minimal implementation: verify HID subsystem is accessible and list devices.
    // Actual Ledger/Trezor APDU flows are out of scope for this issue's initial CLI wiring.
    let api =
        hidapi::HidApi::new().map_err(|e| anyhow::anyhow!("Failed to initialize HID API: {}", e))?;

    let mut count = 0usize;
    for _ in api.device_list() {
        count += 1;
    }

    if count == 0 {
        anyhow::bail!(
            "No HID devices detected. Ensure your {} is connected and unlocked.",
            format!("{:?}", kind).to_lowercase()
        );
    }

    Ok(())
}

#[cfg(not(feature = "hardware-wallet"))]
pub fn sign(_kind: HardwareWalletKind, _message: &[u8]) -> Result<Vec<u8>> {
    anyhow::bail!("Hardware wallet support is disabled in this build.")
}

#[cfg(feature = "hardware-wallet")]
pub fn sign(_kind: HardwareWalletKind, _message: &[u8]) -> Result<Vec<u8>> {
    // Stub: wired for future implementation.
    anyhow::bail!("Hardware wallet signing is not implemented yet.")
}
