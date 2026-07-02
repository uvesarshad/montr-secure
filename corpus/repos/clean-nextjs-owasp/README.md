# clean-nextjs-owasp (golden corpus)

The secured counterpart to `vulnerable-nextjs-owasp`: same routes, each with the
correct control (SSRF allowlist, IDOR ownership check, admin role gate, hardened
cookie flags). A correct scan yields **zero confirmed findings** here — it exists
to catch false positives.
