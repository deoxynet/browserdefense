# Contributing

Use Node.js 22.19+ and pnpm 10.27.0. The extension, CLI, and connector packages are included here. The commercial admin application is maintained separately.

```sh
corepack enable
pnpm install --frozen-lockfile
(cd cli && pnpm install --frozen-lockfile)
pnpm run check
```

Read `docs/Implementation_Review.md`, `docs/Cryptographic_Specification_v3.md`, and `docs/Canonicalization_Specification.md` before changing blocking, update verification, or cryptography.

`pnpm run build:all` builds the consumer extension in `dist/` and the policy-installed enterprise extension in `dist-enterprise/`. Load a build through `chrome://extensions` for manual checks. Manifest content scripts must be self-contained classic JavaScript; the background worker and extension pages use modules.

`pnpm run package` builds and packages both variants. Archives are ignored by Git. Run `pnpm run test:e2e` after installing Playwright Chromium for browser checks; enterprise policy behavior also needs validation on managed endpoints.

Never commit private keys, credentials, environment files, browser profiles, or local cloud emulator state. Generate development keys locally outside the source tree. Run `pnpm run security:scan` before opening a pull request. Use synthetic indicators and generate cryptographic test keys at runtime.

Describe behavior changes and the checks you ran in pull requests. Changes to permissions or cryptography need explicit reviewer attention.
