import { buildPoseidon, type Poseidon } from "circomlibjs";
import { Field } from "@noble/curves/abstract/modular.js";
import { weierstrass, type WeierstrassPoint } from "@noble/curves/abstract/weierstrass.js";

let poseidonInstance: Poseidon | null = null;

export async function initPoseidon(): Promise<void> {
    if (!poseidonInstance) {
        poseidonInstance = await buildPoseidon();
    }
}

function getPoseidon(): Poseidon {
    if (!poseidonInstance) {
        throw new Error("Poseidon not initialized");
    }
    return poseidonInstance;
}

const TREE_DEPTH = 16;

export function poseidonHash2(left: bigint, right: bigint): bigint {
    const poseidon = getPoseidon();
    const hash = poseidon([left, right]);
    return poseidon.F.toObject(hash) as bigint;
}

export function poseidonHash3(v1: bigint, v2: bigint, v3: bigint): bigint {
    const poseidon = getPoseidon();
    const hash = poseidon([v1, v2, v3]);
    return poseidon.F.toObject(hash) as bigint;
}

export function poseidonHash4(v1: bigint, v2: bigint, v3: bigint, v4: bigint): bigint {
    const poseidon = getPoseidon();
    const hash = poseidon([v1, v2, v3, v4]);
    return poseidon.F.toObject(hash) as bigint;
}

// ============================================
// BabyJubJub Curve (BN254's embedded curve)
// ============================================

// BabyJubJub curve parameters
// p (base field) = BN254's scalar field order
// n (scalar field) = BN254's base field order
const BABYJUBJUB_P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const BABYJUBJUB_N = BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583");

// Create the field
const BabyJubJubFp = Field(BABYJUBJUB_P);

// b = -17 mod p
const BABYJUBJUB_B = BabyJubJubFp.neg(17n);

// Generator point coordinates
const BABYJUBJUB_GX = 1n;
const BABYJUBJUB_GY = BigInt("17631683881184975370165255887551781615748388533673675138860");

// Define BabyJubJub curve using noble-curves
const BabyJubJubCurve = weierstrass(
    {
        p: BABYJUBJUB_P,
        n: BABYJUBJUB_N,
        h: 1n,
        a: 0n,
        b: BABYJUBJUB_B,
        Gx: BABYJUBJUB_GX,
        Gy: BABYJUBJUB_GY,
    },
    {
        Fp: BabyJubJubFp,
    }
);

export type BabyJubJubPoint = WeierstrassPoint<bigint>;

// ============================================
// BabyJubJub-style Identity Functions
// ============================================

export interface IdentityKeypair {
    secretKey: bigint;
    publicKey: {
        x: bigint;
        y: bigint;
    };
}

// Max 128-bit value (for EmbeddedCurveScalar compatibility)
const MAX_128_BIT = (1n << 128n) - 1n;

/**
 * Generate a new identity keypair
 * secretKey is a random scalar, publicKey = secretKey * G
 * Note: secretKey must be <= 128 bits for Noir's EmbeddedCurveScalar compatibility
 */
export function generateIdentityKeypair(secretKey: bigint): IdentityKeypair {
    // Ensure secretKey is in valid range and fits in 128 bits
    // This is required because Noir's EmbeddedCurveScalar uses lo/hi 128-bit limbs
    const sk = secretKey % (MAX_128_BIT + 1n);
    
    // Compute public key: secretKey * G (using BASE which is the generator)
    const pk = BabyJubJubCurve.BASE.multiply(sk);
    
    return {
        secretKey: sk,
        publicKey: {
            x: pk.x,
            y: pk.y,
        },
    };
}

/**
 * Calculate wa_commitment = Poseidon(owner_x, owner_y)
 * This is the auditable identity commitment
 */
export function calculateWaCommitment(publicKey: { x: bigint; y: bigint }): bigint {
    return poseidonHash2(publicKey.x, publicKey.y);
}

/**
 * Calculate commitment = Poseidon(owner_x, owner_y, amount, randomness)
 * New commitment scheme with BabyJubJub identity
 */
export function calculateCommitment(
    publicKey: { x: bigint; y: bigint },
    amount: bigint,
    randomness: bigint
): bigint {
    return poseidonHash4(publicKey.x, publicKey.y, amount, randomness);
}

/**
 * Calculate nullifier = Poseidon(secret_key, leaf_index)
 */
export function calculateNullifier(secretKey: bigint, leafIndex: bigint): bigint {
    return poseidonHash2(secretKey, leafIndex);
}

// ============================================
// Merkle Tree Implementation
// ============================================

export class ShieldedPoolMerkleTree {
    private leaves: bigint[] = [];
    private defaultHashes: bigint[];

    constructor() {
        this.defaultHashes = new Array(TREE_DEPTH + 1);
        this.defaultHashes[0] = 0n; // Empty leaf
        for (let i = 1; i <= TREE_DEPTH; i++) {
            const prev = this.defaultHashes[i - 1];
            this.defaultHashes[i] = poseidonHash2(prev, prev);
        }
    }

    insert(commitment: bigint): number {
        const index = this.leaves.length;
        this.leaves.push(commitment);
        return index;
    }

    getRoot(): bigint {
        let currentLevel = [...this.leaves];
        for (let i = 0; i < TREE_DEPTH; i++) {
            const nextLevel: bigint[] = [];
            for (let j = 0; j < Math.pow(2, TREE_DEPTH - i); j += 2) {
                const left = currentLevel[j] ?? this.defaultHashes[i];
                const right = currentLevel[j + 1] ?? this.defaultHashes[i];
                nextLevel.push(poseidonHash2(left, right));
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }

    /**
     * More efficient root calculation for large indices
     */
    getRootOptimized(): bigint {
        return this.calculateRootAtLevel(TREE_DEPTH, 0);
    }

    private calculateRootAtLevel(level: number, index: number): bigint {
        if (level === 0) {
            return this.leaves[index] ?? 0n;
        }
        const left = this.calculateRootAtLevel(level - 1, index * 2);
        const right = this.calculateRootAtLevel(level - 1, index * 2 + 1);
        return poseidonHash2(left, right);
    }

    getProof(index: number): bigint[] {
        const proof: bigint[] = [];
        let currentIdx = index;

        // We need effectively the state of the tree at each level
        let currentLevel = [...this.leaves];

        for (let i = 0; i < TREE_DEPTH; i++) {
            const isRight = currentIdx % 2 === 1;
            const siblingIdx = isRight ? currentIdx - 1 : currentIdx + 1;

            const sibling = currentLevel[siblingIdx] ?? this.defaultHashes[i];
            proof.push(sibling);

            // Move to next level
            const nextLevel: bigint[] = [];
            for (let j = 0; j < Math.pow(2, TREE_DEPTH - i); j += 2) {
                const left = currentLevel[j] ?? this.defaultHashes[i];
                const right = currentLevel[j + 1] ?? this.defaultHashes[i];
                nextLevel.push(poseidonHash2(left, right));
            }
            currentLevel = nextLevel;
            currentIdx = Math.floor(currentIdx / 2);
        }

        return proof;
    }
}
