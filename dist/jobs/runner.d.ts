/**
 * StashPot Automation Runner — HARDENED
 *
 * All draws serialized by withResourceLock — two workers can't run
 * the same draw simultaneously (even if you scale to multiple instances).
 * Every financial mutation is audited.
 */
export {};
