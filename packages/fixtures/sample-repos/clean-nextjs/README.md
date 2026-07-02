# clean-nextjs (fixture)

The safe counterpart of `vulnerable-nextjs`. The scanner must report **zero**
confirmed findings here (false-positive control for the golden corpus).

- Parameterized Prisma query (no raw SQL).
- Auth-gated route (`requireSession`).
- Secret read from the environment (no hard-coded key).
- Pinned, non-vulnerable dependencies.
- Scoped CORS (no wildcard).
