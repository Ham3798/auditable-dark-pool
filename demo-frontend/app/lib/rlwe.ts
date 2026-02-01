// ## SH START ##
// RLWE encryption module for audit circuit integration
// Ported from scripts/generate_audit.py
// Uses ciphertext modulus q = 167772161 (BFV scheme)

const N = 1024;
const RLWE_Q = 167772161n;
const PLAINTEXT_MOD = 256n;
const DELTA = RLWE_Q / PLAINTEXT_MOD; // 655360n
const MSG_SLOTS = 64;
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export { N, RLWE_Q, DELTA, MSG_SLOTS, BN254_P };

interface RlwePk {
  a: bigint[];
  b: bigint[];
}

let cachedPk: RlwePk | null = null;

export async function loadRlwePk(): Promise<RlwePk> {
  if (cachedPk) return cachedPk;
  const res = await fetch("/rlwe/rlwe_pk.json");
  const data = await res.json();
  cachedPk = {
    a: (data.a as string[]).map((h: string) => BigInt(h)),
    b: (data.b as string[]).map((h: string) => BigInt(h)),
  };
  return cachedPk;
}

// Negacyclic polynomial multiplication mod q
// a, b are arrays of length n with values in [0, q)
function negacyclicMulModQ(
  a: bigint[],
  b: bigint[],
  n: number,
  q: bigint
): bigint[] {
  const result = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i++) {
    if (a[i] === 0n) continue;
    for (let j = 0; j < n; j++) {
      if (b[j] === 0n) continue;
      const idx = i + j;
      const prod = a[i] * b[j];
      if (idx < n) {
        result[idx] = ((result[idx] + prod) % q + q) % q;
      } else {
        result[idx - n] = ((result[idx - n] - prod) % q + q) % q;
      }
    }
  }
  return result;
}

// Negacyclic polynomial multiplication over integers (no mod reduction)
// Used for quotient witness computation
function negacyclicMulInt(
  a: bigint[],
  b: bigint[],
  n: number
): bigint[] {
  const result = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i++) {
    if (a[i] === 0n) continue;
    for (let j = 0; j < n; j++) {
      if (b[j] === 0n) continue;
      const idx = i + j;
      const prod = a[i] * b[j];
      if (idx < n) {
        result[idx] += prod;
      } else {
        result[idx - n] -= prod;
      }
    }
  }
  return result;
}

/**
 * Generate row k of negacyclic matrix for polynomial, coefficients mod q.
 * Matches generate_audit.py's negacyclic_matrix_row_mod_q()
 *
 * For negacyclic convolution, the matrix row k is:
 * row[j] = poly[k-j] if k-j >= 0 else (-poly[k-j+n]) % q
 */
function negacyclicMatrixRowModQ(
  poly: bigint[],
  k: number,
  n: number,
  q: bigint
): bigint[] {
  const row: bigint[] = new Array(n).fill(0n);
  for (let j = 0; j < n; j++) {
    const idx = k - j;
    if (idx >= 0) {
      row[j] = ((poly[idx] % q) + q) % q;
    } else {
      row[j] = (((-poly[idx + n]) % q) + q) % q;
    }
  }
  return row;
}

/**
 * Inner product over integers (not mod q).
 * row values are in [0, q), r values are signed small integers.
 */
function innerProductInt(row: bigint[], r: number[]): bigint {
  let sum = 0n;
  for (let i = 0; i < row.length; i++) {
    sum += row[i] * BigInt(r[i]);
  }
  return sum;
}

// Encode a BN254 field element to 8-bit byte slots (little-endian)
export function encodeFieldToBytes(value: bigint, numBytes: number): number[] {
  const slots: number[] = [];
  for (let i = 0; i < numBytes; i++) {
    slots.push(Number((value >> BigInt(i * 8)) & 0xFFn));
  }
  return slots;
}

// Convert signed integer to BN254 field element
export function signedToBn254(v: number | bigint): bigint {
  const vb = BigInt(v);
  return ((vb % BN254_P) + BN254_P) % BN254_P;
}

// Format BN254 field element as hex string for Prover.toml
export function formatField(v: bigint): string {
  const mod = ((v % BN254_P) + BN254_P) % BN254_P;
  if (mod === 0n) return '"0"';
  return `"0x${mod.toString(16).padStart(64, "0")}"`;
}

export interface RlweEncryptResult {
  c0Sparse: bigint[]; // 64 values mod Q
  c1: bigint[]; // 1024 values mod Q
  rSigned: number[]; // 1024 signed noise values
  e1Signed: number[]; // 64 signed noise values
  e2Signed: number[]; // 1024 signed noise values
  msg: number[]; // 64 byte slots
}

function smallNoise(): number {
  const arr = new Uint8Array(1);
  crypto.getRandomValues(arr);
  return (arr[0] % 7) - 3; // [-3, 3]
}

export async function rlweEncrypt(
  ownerX: bigint,
  ownerY: bigint
): Promise<RlweEncryptResult> {
  const pk = await loadRlwePk();

  // Encode message: owner_x (32 bytes) + owner_y (32 bytes) = 64 byte slots
  const msg: number[] = new Array(MSG_SLOTS).fill(0);
  const slotsX = encodeFieldToBytes(ownerX, 32);
  for (let i = 0; i < 32; i++) msg[i] = slotsX[i];
  const slotsY = encodeFieldToBytes(ownerY, 32);
  for (let i = 0; i < 32; i++) msg[32 + i] = slotsY[i];

  // Generate small noise
  const rSigned: number[] = Array.from({ length: N }, () => smallNoise());
  const e1Signed: number[] = Array.from({ length: MSG_SLOTS }, () => smallNoise());
  const e2Signed: number[] = Array.from({ length: N }, () => smallNoise());

  const mod = (v: bigint, q: bigint) => ((v % q) + q) % q;
  const rModQ = rSigned.map((v) => mod(BigInt(v), RLWE_Q));
  const e1ModQ = e1Signed.map((v) => mod(BigInt(v), RLWE_Q));
  const e2ModQ = e2Signed.map((v) => mod(BigInt(v), RLWE_Q));

  // c0_sparse[i] = inner_product(PK_B_ROW[i], r) + e1[i] + DELTA*msg[i] mod q
  // Using inner product with negacyclic matrix row to match circuit verification
  const c0Sparse: bigint[] = [];
  for (let i = 0; i < MSG_SLOTS; i++) {
    const row = negacyclicMatrixRowModQ(pk.b, i, N, RLWE_Q);
    let ip = 0n;
    for (let j = 0; j < N; j++) {
      ip = ((ip + row[j] * rModQ[j]) % RLWE_Q + RLWE_Q) % RLWE_Q;
    }
    c0Sparse.push(mod(ip + e1ModQ[i] + DELTA * BigInt(msg[i]), RLWE_Q));
  }

  // c1[i] = inner_product(PK_A_ROW[i], r) + e2[i] mod q
  // Using inner product with negacyclic matrix row to match circuit verification
  const c1: bigint[] = [];
  for (let i = 0; i < N; i++) {
    const row = negacyclicMatrixRowModQ(pk.a, i, N, RLWE_Q);
    let ip = 0n;
    for (let j = 0; j < N; j++) {
      ip = ((ip + row[j] * rModQ[j]) % RLWE_Q + RLWE_Q) % RLWE_Q;
    }
    c1.push(mod(ip + e2ModQ[i], RLWE_Q));
  }

  return { c0Sparse, c1, rSigned, e1Signed, e2Signed, msg };
}

export interface QuotientResult {
  k0: bigint[]; // 64 signed bigints
  k1: bigint[]; // 1024 signed bigints
}

export async function computeQuotients(
  c0Sparse: bigint[],
  c1: bigint[],
  rSigned: number[],
  e1Signed: number[],
  e2Signed: number[],
  msg: number[]
): Promise<QuotientResult> {
  const pk = await loadRlwePk();

  // k0 계산: inner_product(PK_B_ROWS[i], r) 방식
  // This matches the circuit's verification: inner_product_const(PK_B_ROWS[i], r)
  const k0: bigint[] = [];
  for (let i = 0; i < MSG_SLOTS; i++) {
    const row = negacyclicMatrixRowModQ(pk.b, i, N, RLWE_Q);
    const ipInt = innerProductInt(row, rSigned);
    const fullVal = ipInt + BigInt(e1Signed[i]) + DELTA * BigInt(msg[i]);
    const c0Val = c0Sparse[i];
    const k = (fullVal - c0Val) / RLWE_Q;
    k0.push(k);
  }

  // k1 계산: inner_product(PK_A_ROWS[i], r) 방식
  // This matches the circuit's verification: inner_product_const(PK_A_ROWS[i], r)
  const k1: bigint[] = [];
  for (let i = 0; i < N; i++) {
    const row = negacyclicMatrixRowModQ(pk.a, i, N, RLWE_Q);
    const ipInt = innerProductInt(row, rSigned);
    const fullVal = ipInt + BigInt(e2Signed[i]);
    const c1Val = c1[i];
    const k = (fullVal - c1Val) / RLWE_Q;
    k1.push(k);
  }

  return { k0, k1 };
}

// Generate Audit Prover.toml content
export function generateAuditProverToml(params: {
  secretKey: bigint;
  waCommitment: bigint;
  ctCommitment: bigint | null;
  c0Sparse: bigint[];
  c1: bigint[];
  rSigned: number[];
  e1Signed: number[];
  e2Signed: number[];
  k0: bigint[];
  k1: bigint[];
}): string {
  const {
    secretKey,
    waCommitment,
    ctCommitment,
    c0Sparse,
    c1,
    rSigned,
    e1Signed,
    e2Signed,
    k0,
    k1,
  } = params;

  let toml = `# Audit Prover.toml - Copy this to audit_circuit/Prover.toml\n`;
  toml += `secret_key = ${formatField(secretKey)}\n`;
  toml += `wa_commitment = ${formatField(waCommitment)}\n`;
  if (ctCommitment !== null) {
    toml += `ct_commitment = ${formatField(ctCommitment)}\n`;
  } else {
    toml += `# ct_commitment must be computed via CLI (nargo execute in ct_helper_v2)\n`;
    toml += `ct_commitment = "0"\n`;
  }
  toml += `c0_sparse = [${c0Sparse.map((v) => formatField(v)).join(", ")}]\n`;
  toml += `c1 = [${c1.map((v) => formatField(v)).join(", ")}]\n`;
  toml += `r = [${rSigned.map((v) => formatField(signedToBn254(v))).join(", ")}]\n`;
  toml += `e1_sparse = [${e1Signed.map((v) => formatField(signedToBn254(v))).join(", ")}]\n`;
  toml += `e2 = [${e2Signed.map((v) => formatField(signedToBn254(v))).join(", ")}]\n`;
  toml += `k0 = [${k0.map((v) => formatField(signedToBn254(v))).join(", ")}]\n`;
  toml += `k1 = [${k1.map((v) => formatField(signedToBn254(v))).join(", ")}]\n`;

  return toml;
}
// ## SH END ##
