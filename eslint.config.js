// Flat ESLint config for the Montr Secure monorepo.
// ENFORCES GOLDEN RULE #2: no provider SDK may be imported outside @montr/llm-gateway.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";
import globals from "globals";

/** Provider SDKs that must never appear outside the gateway. */
const BANNED_PROVIDER_PACKAGES = [
  "@anthropic-ai/sdk",
  "@anthropic-ai/bedrock-sdk",
  "@anthropic-ai/vertex-sdk",
  "@aws-sdk/client-bedrock-runtime",
  "@google-cloud/vertexai",
  "@google/generative-ai",
  "@azure/openai",
  "openai",
  "cohere-ai",
];

const providerBan = {
  "no-restricted-imports": [
    "error",
    {
      paths: BANNED_PROVIDER_PACKAGES.map((name) => ({
        name,
        message:
          "GOLDEN RULE #2 (§8.2): provider SDKs may only be imported inside @montr/llm-gateway. Depend on the gateway interface from @montr/contracts instead.",
      })),
      patterns: [
        {
          group: ["@anthropic-ai/*", "@mistralai/*"],
          message:
            "GOLDEN RULE #2 (§8.2): provider SDKs may only be imported inside @montr/llm-gateway.",
        },
      ],
    },
  ],
};

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/.turbo/**",
      "**/coverage/**",
      "**/*.tsbuildinfo",
      // Fixture sample repos contain INTENTIONALLY vulnerable code — never lint them.
      "packages/fixtures/sample-repos/**",
      // Golden corpus (corpus/README.md) — vendored real-world + intentionally
      // vulnerable snapshots, out-of-tree source styles. Never lint/format them.
      "corpus/**",
      "deploy/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: {
      ...providerBan,
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "no-console": "off",
    },
  },
  {
    // The gateway is the ONE place a provider SDK may live.
    files: ["packages/llm-gateway/**"],
    rules: { "no-restricted-imports": "off" },
  },
  prettier,
);
