// VULN #3 (CWE-798): hard-coded live secret. Line 2 below.
export const PAYMENTS_API_KEY = "sk_live_51H8xEXAMPLEhardcodedKeyDoNotUse0000";
export const config = { apiKey: PAYMENTS_API_KEY };
