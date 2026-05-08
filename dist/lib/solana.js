import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import bs58 from 'bs58';
const RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com';
// 1. Connect to devnet
export const connection = new Connection(RPC_URL, 'confirmed');
// 2. Load wallet from environment variable or generate ephemeral one
export const getDeployerKeypair = () => {
    const privateKeyBase58 = process.env.SOLANA_PRIVATE_KEY;
    if (privateKeyBase58) {
        try {
            const secretKey = bs58.decode(privateKeyBase58);
            return Keypair.fromSecretKey(secretKey);
        }
        catch (err) {
            console.error('[solana] Failed to decode SOLANA_PRIVATE_KEY, using ephemeral keypair');
        }
    }
    // Generate ephemeral keypair (WARNING: will change on every deploy)
    console.warn('[solana] No SOLANA_PRIVATE_KEY found, using ephemeral keypair');
    return Keypair.generate();
};
// 3. Create wallet instance
export const wallet = getDeployerKeypair();
// 4. Helper
export const publicKey = wallet.publicKey.toBase58();
// 5. Program ID - use a valid placeholder or from env
export const PROGRAM_ID = process.env.STASHPOT_PROGRAM_ID
    ? new PublicKey(process.env.STASHPOT_PROGRAM_ID)
    : Keypair.generate().publicKey; // Generate valid placeholder if not set
//# sourceMappingURL=solana.js.map