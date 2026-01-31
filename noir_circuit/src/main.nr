use dep::poseidon::poseidon::bn254::hash_2 as poseidon_hash;
use dep::poseidon::poseidon::bn254::hash_4 as poseidon_hash_4;
use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

global TREE_DEPTH: u32 = 16;

fn poseidon_hash_2(left: Field, right: Field) -> Field {
    poseidon_hash([left, right])
}

fn compute_merkle_root<let N: u32>(leaf: Field, index: Field, siblings: [Field; N]) -> Field {
    let mut current = leaf;
    let path_bits: [u1; N] = index.to_le_bits();

    for i in 0..N {
        let sibling = siblings[i];
        let bit = path_bits[i];

        let (left, right) = if bit == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };

        current = poseidon_hash_2(left, right);
    }

    current
}

// BabyJubJub-based Shielded Pool Withdraw Circuit
// 
// New commitment scheme with auditable identity:
// - (owner_x, owner_y) = secret_key * G  (BabyJubJub generator)
// - wa_commitment = Poseidon(owner_x, owner_y)  (auditable identity for RLWE)
// - commitment = Poseidon(owner_x, owner_y, amount, randomness)
// - nullifier = Poseidon(secret_key, leaf_index)
fn main(
    // Public inputs
    root: pub Field,
    nullifier: pub Field,
    recipient: pub Field,
    amount: pub u64,
    wa_commitment: pub Field, // auditable commitment for RLWE audit module
    
    // Private inputs
    secret_key: Field,        // private key
    owner_x: Field,           // public key x coordinate
    owner_y: Field,           // public key y coordinate
    randomness: Field,        // commitment randomness
    index: Field,
    siblings: [Field; TREE_DEPTH]
) {
    // 1. Verify public key derivation: secret_key * G == (owner_x, owner_y)
    // Split secret_key into low/high 128-bit limbs for EmbeddedCurveScalar
    let two_pow_128: Field = 0x100000000000000000000000000000000;
    let secret_low = secret_key as u128;
    let secret_high = ((secret_key - secret_low as Field) / two_pow_128) as u128;
    let scalar = EmbeddedCurveScalar::new(secret_low as Field, secret_high as Field);
    let pk = fixed_base_scalar_mul(scalar);
    assert(pk.x == owner_x, "Public key X mismatch");
    assert(pk.y == owner_y, "Public key Y mismatch");
    
    // 2. Verify wa_commitment = Poseidon(owner_x, owner_y)
    // This will be logged on-chain for audit purposes
    let calculated_wa = poseidon_hash_2(owner_x, owner_y);
    assert(wa_commitment == calculated_wa, "wa_commitment mismatch");
    
    // 3. Commitment = Poseidon(owner_x, owner_y, amount, randomness)
    let commitment = poseidon_hash_4([owner_x, owner_y, amount as Field, randomness]);
    
    // 4. Nullifier = Poseidon(secret_key, leaf_index)
    let calculated_nullifier = poseidon_hash_2(secret_key, index);
    assert(nullifier == calculated_nullifier, "Nullifier mismatch");
    
    // 5. Verify Merkle membership
    let calculated_root = compute_merkle_root(commitment, index, siblings);
    assert(root == calculated_root, "Merkle root mismatch");
    
    // 6. Bind proof to recipient
    assert(recipient != 0, "Recipient cannot be zero");
}

#[test]
fn test_shielded_pool_babyjubjub() {
    // Test with a known secret key
    let secret_key: Field = 12345;
    let index: Field = 0;
    let amount: u64 = 1000000; // 1M lamports
    let randomness: Field = 67890;
    let recipient: Field = 123;
    
    // Derive public key using fixed_base_scalar_mul
    // Split secret_key into low/high 128-bit limbs
    let two_pow_128: Field = 0x100000000000000000000000000000000;
    let secret_low = secret_key as u128;
    let secret_high = ((secret_key - secret_low as Field) / two_pow_128) as u128;
    let scalar = EmbeddedCurveScalar::new(secret_low as Field, secret_high as Field);
    let pk = fixed_base_scalar_mul(scalar);
    let owner_x = pk.x;
    let owner_y = pk.y;
    
    // Calculate wa_commitment
    let wa_commitment = poseidon_hash_2(owner_x, owner_y);
    
    // Calculate commitment
    let commitment = poseidon_hash_4([owner_x, owner_y, amount as Field, randomness]);
    
    // Calculate nullifier
    let nullifier = poseidon_hash_2(secret_key, index);
    
    // Build merkle tree with single leaf
    let siblings = [0; TREE_DEPTH];
    let root = compute_merkle_root(commitment, index, siblings);
    
    // Run main circuit
    main(
        root, 
        nullifier, 
        recipient, 
        amount, 
        wa_commitment,
        secret_key, 
        owner_x, 
        owner_y, 
        randomness, 
        index, 
        siblings
    );
}
