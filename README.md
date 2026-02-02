# Shielded Pool

**One-line description**
Privacy-preserving SOL transfers on Solana using Noir ZK proofs with BabyJubJub auditable identity.

**GitHub**
https://github.com/Ham3798/shielded-pool-pinocchio-solana

**Presentation video**


**Live demo**


**Track**


**Sponsor bounties**


## Technical Detail

Shielded Pool is a ZK-based privacy pool for Solana that enables anonymous SOL transfers while maintaining auditability.

**Stack:**
- **Noir**: ZK circuit for proving valid withdrawals without revealing deposit details. The circuit verifies Merkle tree membership, nullifier uniqueness, and BabyJubJub identity ownership.
- **Sunspot**: Compiles Noir proofs to Solana-compatible Groth16 format for on-chain verification.
- **Pinocchio**: Lightweight Solana program framework for the pool and verifier contracts.
- **BabyJubJub**: Embedded curve on BN254 for auditable identity (wa_commitment), enabling future 2-of-3 threshold audit capability.
- **Poseidon Hash**: ZK-friendly hash for commitments, nullifiers, and Merkle tree construction.

**Commitment scheme:**
```
(owner_x, owner_y) = secret_key * G          // BabyJubJub
wa_commitment = Poseidon(owner_x, owner_y)   // Auditable identity
commitment = Poseidon(owner_x, owner_y, amount, randomness)
nullifier = Poseidon(secret_key, leaf_index)
```

## RLWE Audit Circuit (audit2 branch)

The audit circuit proves that a BFV ciphertext was correctly encrypted under the auditor's RLWE public key, enabling regulatory compliance without breaking user privacy.

**What it verifies:**
- **Ownership**: BJJ scalar multiplication + Poseidon wa_commitment
- **Encryption correctness**: BFV encryption equations c0 = b·r + e1 + Δ·msg (mod q), c1 = a·r + e2 (mod q), verified via batched inner-product checks
- **Noise bounds**: range proofs on r, e1, e2 (small noise values)
- **Ciphertext integrity**: Poseidon2 sponge commitment over packed ciphertext

**Soundness**: attack probability ≤ 1024 / |BN254| ≈ 2⁻²⁴⁴

**Parameters**: N = 1024, q = 65537, t = 256, Δ = 256, MSG_SLOTS = 64

### Benchmark

| Metric | Value |
|--------|-------|
| Circuit source | 7.8 KB |
| Constraints | 113K |
| nargo compile | 1.9s |
| nargo execute | 0.4s |
| sunspot prove | 2.4s |
| sunspot verify | 0.06s |
| Proof size | 388 bytes |
| .ccs | 7.2 MB |
| Proving key | ~5 MB |

### Usage

```bash
# Generate circuit + Prover.toml + run full pipeline
python scripts/generate_audit.py

# Or run proof pipeline separately
cd audit_circuit
./prove_audit.sh
```

## Roadmap

- Browser-based proof generation (WASM)
- Verifiable FHE computation: extend batched IP verification to bootstrapping and keyswitching, combined with IVC for sequential operations
- On-chain auditor decryption flow with threshold FHE key management
- Multi-asset support (SPL tokens)
- Relayer network for gas abstraction

**Telegram**


---

## Architecture

```
Shielded Pool
├─ noir_circuit/                  # Withdrawal proof
│  ├─ nargo execute -> witness (.gz)
│  └─ sunspot prove -> proof (.proof) + public witness (.pw)
├─ audit_circuit/                 # RLWE audit proof (BFV encryption correctness)
│  ├─ generate_audit.py -> main.nr + Prover.toml
│  └─ sunspot prove -> audit proof (.proof) + public witness (.pw)
├─ verifier program (Sunspot Groth16)
│  └─ verifies proof + public witness
└─ shielded_pool_program/
   ├─ initialize/deposit/withdraw
   ├─ checks root/nullifier/recipient/amount
   └─ CPI to verifier program
```

***DISCLAIMER: This repository has not been audited. Use at your own risk.***

### Flow

1. **Initialize**: relayer creates state + vault PDAs
2. **Deposit**: sender transfers SOL into vault, updates Merkle root
3. **Withdraw**: relayer submits proof, program verifies, releases SOL to recipient

## Prerequisites

- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation) `1.0.0-beta.13`
- [Sunspot](https://github.com/reilabs/sunspot) `5fd6223` (Go 1.24+, compatible with Noir 1.0.0-beta.13)
- [Solana CLI](https://solana.com/docs/intro/installation)
- Node.js 18+

```bash
# Noir
noirup -v 1.0.0-beta.13

# Sunspot (must use commit 5fd6223 for Noir 1.0.0-beta.13 compatibility)
git clone https://github.com/reilabs/sunspot.git ~/sunspot
cd ~/sunspot && git checkout 5fd6223
cd go && go build -o sunspot .
export PATH="$HOME/sunspot/go:$PATH"
export GNARK_VERIFIER_BIN="$HOME/sunspot/gnark-solana/crates/verifier-bin"
```

## Project Structure

```
.
├── noir_circuit/               # Noir circuit + proving artifacts
├── shielded_pool_program/      # Pinocchio program
├── client/                     # TS integration test
├── demo-frontend/              # Next.js demo UI
└── keypair/                    # Local keypairs (gitignored)
```

## Build and Deploy

### 1) Circuit artifacts

Pre-compiled artifacts (`.ccs`, `.pk`, `.vk`, `.json`) are included in the repository, so you can skip the compile and setup steps and go directly to proof generation.

**Quick start (using pre-compiled artifacts):**
```bash
cd noir_circuit
# Edit Prover.toml with your inputs
nargo execute
sunspot prove target/shielded_pool_verifier.json target/shielded_pool_verifier.gz target/shielded_pool_verifier.ccs target/shielded_pool_verifier.pk
sunspot deploy target/shielded_pool_verifier.vk
```

**Full build (if you need to regenerate artifacts):**
```bash
cd noir_circuit
nargo compile
nargo execute
sunspot compile target/shielded_pool_verifier.json
sunspot setup target/shielded_pool_verifier.ccs
sunspot prove target/shielded_pool_verifier.json target/shielded_pool_verifier.gz target/shielded_pool_verifier.ccs target/shielded_pool_verifier.pk
sunspot deploy target/shielded_pool_verifier.vk
```

### 2) Deploy verifier program

```bash
solana program deploy path/to/verifier.so --url devnet
```

### 3) Deploy shielded pool program

Update verifier program ID in `shielded_pool_program/src/instructions/withdraw.rs`, then:

```bash
cargo build-sbf --manifest-path shielded_pool_program/Cargo.toml
solana program deploy shielded_pool_program/target/deploy/shielded_pool_pinocchio.so --url devnet
```

## Run Integration Test

```bash
RPC_URL=https://api.devnet.solana.com \
ZK_VERIFIER_PROGRAM_ID=<verifier_program_id> \
SHIELDED_POOL_PROGRAM_ID=<shielded_pool_program_id> \
pnpm --dir client run test-shielded-pool
```

## Resources

- [Noir Documentation](https://noir-lang.org/docs/)
- [Sunspot Repository](https://github.com/reilabs/sunspot)
- [Pinocchio Library](https://github.com/anza-xyz/pinocchio)
