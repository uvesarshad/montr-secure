/**
 * Deterministic identifiers and timestamps. Fixtures must be DETERMINISTIC —
 * no Date.now()/random anywhere in this package (offline golden-corpus tests).
 */
export const FIXED_NOW = "2026-01-15T10:00:00.000Z";
export const FIXED_LATER = "2026-01-15T10:05:00.000Z";

export const CLIENT_ID = "client_fixture_0001";
export const SCAN_ID = "scan_fixture_0001";
export const APPMAP_ID = "appmap_fixture_0001";
export const CLEAN_APPMAP_ID = "appmap_fixture_clean_0001";
export const COMMIT_SHA = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

export const OPERATOR_ID = "user_operator_0001";
export const APPROVER_ID = "user_approver_0001";

export const ROUTE_USERS_ID = "route_users_0001";
export const ROUTE_SEARCH_ID = "route_search_0001";

export const CANDIDATE_SQLI_ID = "cand_sqli_0001";
export const CANDIDATE_XSS_ID = "cand_xss_0001";
export const CANDIDATE_SECRET_ID = "cand_secret_0001";
export const CANDIDATE_DEP_ID = "cand_dep_0001";
export const CANDIDATE_CORS_ID = "cand_cors_0001";

export const PROBABLE_SQLI_ID = "prob_sqli_0001";
export const PROBABLE_XSS_ID = "prob_xss_0001";
export const PROBABLE_CORS_ID = "prob_cors_0001";

export const CONFIRMED_SQLI_ID = "conf_sqli_0001";
export const CONFIRMED_XSS_ID = "conf_xss_0001";

export const FIX_SQLI_ID = "fix_sqli_0001";
export const FIX_XSS_ID = "fix_xss_0001";
export const PR_ID = "pr_0001";
export const REPORT_ID = "report_0001";

export const REPO_URL = "https://example.internal/montr/vulnerable-nextjs";
export const BRANCH = "main";
