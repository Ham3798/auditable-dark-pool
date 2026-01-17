use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use solana_program_error::ProgramError;
use solana_program_log::log;

use crate::state::ShieldedPoolState;

pub fn process_initialize(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let [payer, state_account, vault, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !state_account.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Ensure the state account matches the expected PDA.
    let (pda, bump) = Address::find_program_address(&[b"pool_state"], &crate::ID);
    if state_account.address() != &pda {
        return Err(ProgramError::InvalidAccountData);
    }

    if !state_account.is_data_empty() && !state_account.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    if state_account.is_data_empty() {
        let rent = Rent::get()?;
        let space = ShieldedPoolState::LEN as u64;
        let lamports = rent.try_minimum_balance(space as usize)?;

        let bump_seed = [bump];
        let seeds = [Seed::from(b"pool_state"), Seed::from(&bump_seed)];
        let signer = [Signer::from(&seeds)];

        log("Creating ShieldedPoolState account");
        CreateAccount {
            from: payer,
            to: state_account,
            lamports,
            space,
            owner: &crate::ID,
        }
        .invoke_signed(&signer)?;
    }

    // Initialize state data.
    let mut data = state_account.try_borrow_mut()?;
    let state: &mut ShieldedPoolState =
        bytemuck::from_bytes_mut(&mut data[..ShieldedPoolState::LEN]);

    if state.is_initialized() {
        log("ShieldedPoolState already initialized");
        return Ok(());
    }

    state.discriminator = ShieldedPoolState::DISCRIMINATOR;
    state.current_root = [0u8; 32]; // Initial root is zero.
    state.roots = [[0u8; 32]; 32];
    state.roots_index = 0;
    state._padding = [0u8; 4];

    // Create the vault PDA if missing.
    let (vault_pda, vault_bump) = Address::find_program_address(&[b"vault"], &crate::ID);
    if vault.address() != &vault_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    if vault.lamports() > 0 && !vault.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    if vault.is_data_empty() && vault.lamports() == 0 {
        let rent = Rent::get()?;
        let space = 0u64;
        let lamports = rent.try_minimum_balance(space as usize)?;

        let bump_seed = [vault_bump];
        let seeds = [Seed::from(b"vault"), Seed::from(&bump_seed)];
        let signer = [Signer::from(&seeds)];

        log("Creating vault PDA");
        CreateAccount {
            from: payer,
            to: vault,
            lamports,
            space,
            owner: &crate::ID,
        }
        .invoke_signed(&signer)?;
    }

    log("ShieldedPoolState initialized");
    Ok(())
}
