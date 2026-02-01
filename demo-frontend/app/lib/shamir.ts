// ## SH START ##
// Shamir secret reconstruction + RLWE decryption
// Ported from scripts/rlwe_decrypt.py

const N = 1024;
const MSG_SLOTS = 64;
const RLWE_Q = 167772161n;
const PLAINTEXT_MOD = 256n;
const DELTA = RLWE_Q / PLAINTEXT_MOD; // 655360n
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

interface ShareCoefficient {
  x: number;
  y: string; // hex string
}

interface ShareFile {
  share_index: number;
  threshold: number;
  num_shares: number;
  coefficients: ShareCoefficient[];
}

// Modular exponentiation for BigInt
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// Lagrange interpolation at x=0 over BN254 field
function shamirReconstructField(
  shares: [number, bigint][],
  threshold: number
): bigint {
  let secret = 0n;
  const xs = shares.slice(0, threshold).map((s) => BigInt(s[0]));
  const ys = shares.slice(0, threshold).map((s) => s[1]);

  for (let i = 0; i < threshold; i++) {
    let num = ys[i];
    for (let j = 0; j < threshold; j++) {
      if (i !== j) {
        num = (num * ((-xs[j] % BN254_P) + BN254_P)) % BN254_P;
        const inv = modPow(
          ((xs[i] - xs[j]) % BN254_P + BN254_P) % BN254_P,
          BN254_P - 2n,
          BN254_P
        );
        num = (num * inv) % BN254_P;
      }
    }
    secret = (secret + num) % BN254_P;
  }
  return secret;
}

function centeredMod(v: bigint, q: bigint): bigint {
  v = ((v % q) + q) % q;
  if (v > q / 2n) v -= q;
  return v;
}

// Negacyclic polynomial multiplication mod q
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

// Reconstruct sk from 2 share files, return sk mod q
export async function reconstructSk(
  share1Data: ShareFile,
  share2Data: ShareFile
): Promise<bigint[]> {
  const threshold = share1Data.threshold;
  const skModQ: bigint[] = [];

  for (let coeffIdx = 0; coeffIdx < N; coeffIdx++) {
    const s1: [number, bigint] = [
      share1Data.coefficients[coeffIdx].x,
      BigInt(share1Data.coefficients[coeffIdx].y),
    ];
    const s2: [number, bigint] = [
      share2Data.coefficients[coeffIdx].x,
      BigInt(share2Data.coefficients[coeffIdx].y),
    ];
    const val = shamirReconstructField([s1, s2], threshold);
    // Convert BN254 → signed → mod q
    const signed = centeredMod(val, BN254_P);
    skModQ.push(((signed % RLWE_Q) + RLWE_Q) % RLWE_Q);
  }

  return skModQ;
}

// Load bundled share files from public/rlwe/
export async function loadBundledShares(): Promise<[ShareFile, ShareFile]> {
  const [res1, res2] = await Promise.all([
    fetch("/rlwe/rlwe_sk_shares/share_1.json"),
    fetch("/rlwe/rlwe_sk_shares/share_2.json"),
  ]);
  const share1 = await res1.json();
  const share2 = await res2.json();
  return [share1, share2];
}

// Decrypt RLWE ciphertext using reconstructed sk
export function rlweDecrypt(
  c0Sparse: bigint[],
  c1: bigint[],
  skModQ: bigint[]
): { ownerX: bigint; ownerY: bigint } {
  // sk * c1 (negacyclic mul mod q)
  const skC1 = negacyclicMulModQ(skModQ, c1, N, RLWE_Q);

  // Recover message slots
  const msgRecovered: number[] = [];
  for (let i = 0; i < MSG_SLOTS; i++) {
    const noisy = (c0Sparse[i] + skC1[i]) % RLWE_Q;
    const noisyCentered = centeredMod(noisy, RLWE_Q);
    // round(noisy / Delta) mod t
    const val =
      Number(
        ((noisyCentered * 10n) / DELTA + (noisyCentered >= 0n ? 5n : -5n)) /
          10n
      ) % Number(PLAINTEXT_MOD);
    msgRecovered.push(((val % 256) + 256) % 256);
  }

  // Reassemble owner_x from bytes 0..31
  let ownerX = 0n;
  for (let i = 0; i < 32; i++) {
    ownerX += BigInt(msgRecovered[i] & 0xff) << BigInt(i * 8);
  }

  // Reassemble owner_y from bytes 32..63
  let ownerY = 0n;
  for (let i = 0; i < 32; i++) {
    ownerY += BigInt(msgRecovered[32 + i] & 0xff) << BigInt(i * 8);
  }

  return { ownerX, ownerY };
}

// Full decryption flow: load shares → reconstruct → decrypt
export async function decryptFromShares(
  c0Sparse: bigint[],
  c1: bigint[]
): Promise<{ ownerX: bigint; ownerY: bigint }> {
  const [share1, share2] = await loadBundledShares();
  const skModQ = await reconstructSk(share1, share2);
  return rlweDecrypt(c0Sparse, c1, skModQ);
}
// ## SH END ##
