import { Connection, Keypair } from "@solana/web3.js";
import fs from "fs";
const RPC_URL = "https://api.devnet.solana.com";
// 1. Connect to devnet
export const connection = new Connection(RPC_URL, "confirmed");
// 2. Load wallet from Solana CLI keypair
const secret = JSON.parse(fs.readFileSync(process.env.SOLANA_KEYPAIR_PATH ||
    "/home/daimey/.config/solana/stashpot-deploy.json", "utf-8"));
// 3. Create Keypair
export const wallet = Keypair.fromSecretKey(new Uint8Array(secret));
// 4. helper
export const publicKey = wallet.publicKey.toBase58();
//# sourceMappingURL=solana.js.map