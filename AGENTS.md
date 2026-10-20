# BrowserDefense Agent Guidelines

## The Mission

Build a Chrome extension that blocks IOCs at the browser level with zero-knowledge forensics. The extension, CLI, and worker services are implemented; use the specifications and tests to evaluate changes.

**Start by reading the specs in `docs/`**, especially `Implementation_Review.md`.

## What We're Building (MVP)

1. **Chrome extension skeleton** - manifest.json, service worker, popup
2. **Crypto module** - X25519 + HKDF + AES-GCM (Team Mesh/Threat Feeds), RSA-OAEP + AES-GCM (Forensics)
3. **Hash storage** - Binary compact format (NOT JSON arrays)
4. **Blocking logic** - Navigation interception via webNavigation API
5. **Forensics capture** - Redirect chains, timestamps, context

## Critical Technical Decisions (Already Made)

- **X25519** for Team Mesh/Threat Feeds - verify WebCrypto support in target Chrome versions
- **Binary ArrayBuffer** for hash storage - JSON hits 10MB limits
- **4.9 min heartbeat** for service worker keep-alive

## Workflow

1. Work on a feature branch and use worktrees for isolation.
2. Preserve in-progress changes made by others.
3. Run the checks in CONTRIBUTING.md before opening a pull request.
4. Never commit private keys, credentials, local cloud state, or generated release archives.

## Development Commands

```bash
pnpm install --frozen-lockfile               # Install deps
pnpm run dev               # Build with watch
pnpm test                  # Run tests
pnpm run build             # Production build
```

## Filing Issues

- Use `kaizen` label for improvement observations
- Use `meta:improvement` for workflow/process improvements

## Spec Documents (READ THESE)

| Document | Priority |
|----------|----------|
| `docs/Implementation_Review.md` | P0 - Critical fixes |
| `docs/Cryptographic_Specification_v3.md` | P0 - Crypto details |
| `docs/Architecture_Hardening_Specification.md` | P1 - Reliability |
| `docs/Project_Charter_BlockIOC_Updated_v2.md` | P2 - Context |
