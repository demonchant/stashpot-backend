import express from "express";
import { connection, wallet } from "../lib/solana.js";

const router = express.Router();

router.get("/balance", async (req, res) => {
  try {
    const balance = await connection.getBalance(wallet.publicKey);

    res.json({
      wallet: wallet.publicKey.toBase58(),
      balanceLamports: balance,
      balanceSOL: balance / 1e9
    });
  } catch (err: any) {
  res.status(500).json({ error: err?.message || "Internal error" });
}
});

export default router;
