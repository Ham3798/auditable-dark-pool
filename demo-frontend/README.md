# Demo Frontend

Shielded Pool demo web UI for the Auditable Dark Pool (🪿 Honk). See [project root README](../README.md) for main documentation.

## Run

```bash
npm install
npm run dev
```

## Environment Variables

`.env.local`:
```env
# Helius RPC (recommended) - Get your free API key at https://dev.helius.xyz/
# If not set, falls back to Solana devnet RPC
NEXT_PUBLIC_SOLANA_RPC_URL=https://devnet.helius-rpc.com/?api-key=YOUR_HELIUS_API_KEY
NEXT_PUBLIC_SHIELDED_POOL_PROGRAM_ID=H76rmbsE6HxkDw7AWEJLtqYogyP6psq3Fk2wqPH7Cjes
NEXT_PUBLIC_ZK_VERIFIER_PROGRAM_ID=3qfJCYMTnPwFgSX1T3Ncem6b5DphHtNoMmgyVeb52Yti
```

> **Note:** This project uses [Helius RPC](https://helius.dev/) as the primary RPC provider for improved performance. If Helius RPC is not configured, it automatically falls back to the default Solana devnet RPC.

## Deploy

```bash
vercel --prod
```
