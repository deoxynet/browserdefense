# E2E Tests for BrowserDefense Extension

End-to-end tests using Playwright for the Chrome extension.

## Chrome Extension Headless Mode Limitation

**Chrome extensions cannot be loaded in headless mode.** This is a fundamental Chrome/Chromium limitation, not a Playwright or test framework issue.

When Chrome runs in headless mode, the extension APIs are not available and `--load-extension` is silently ignored. Tests will either fail or pass incorrectly because the extension simply isn't there.

### Running Tests Locally

```bash
# Run with visible browser (required for extension tests)
npm run test:e2e:headed

# Or explicitly:
npx playwright test --headed
```

### Running Tests in CI

For CI environments without a display, use `xvfb-run` to provide a virtual display:

```bash
# Install xvfb (Ubuntu/Debian)
sudo apt-get install xvfb

# Run tests with virtual display
xvfb-run npx playwright test
```

#### GitHub Actions Example

```yaml
- name: Install dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y xvfb

- name: Run E2E tests
  run: xvfb-run npm run test:e2e
```

#### Docker Example

Use a Docker image with Xvfb pre-configured:

```dockerfile
FROM mcr.microsoft.com/playwright:v1.48.0-jammy

RUN apt-get update && apt-get install -y xvfb

CMD ["xvfb-run", "npx", "playwright", "test"]
```

## Test Structure

- `fixtures.ts` - Custom Playwright fixtures for loading the extension
- `extension.spec.ts` - Basic extension lifecycle tests
- `block-navigation.spec.ts` - URL blocking functionality
- `forensics-capture.spec.ts` - Forensics data capture
- `screenshots/*.spec.ts` - Visual regression tests

## Fixtures

The test fixtures in `fixtures.ts` handle:

1. Launching Chrome with the extension loaded via `--load-extension`
2. Extracting the dynamic extension ID from the service worker URL
3. Providing helpers to open popup, options, and blocked pages

### Headless Detection

The fixtures include a runtime check that will fail fast if headless mode is detected:

```typescript
if (process.env.PLAYWRIGHT_HEADLESS === '1') {
  throw new Error(
    'Chrome extensions cannot run in headless mode. ' +
    'Use --headed flag or xvfb-run for CI.'
  );
}
```

This prevents silent failures where tests pass because the extension wasn't loaded.

## Common Issues

### Tests pass but extension isn't working

You're probably running in headless mode. Use `--headed` or `xvfb-run`.

### Extension ID is empty

The service worker may not have registered yet. The fixtures wait up to 5 seconds for registration.

### Tests are slow

Extension tests are inherently slower because:
- They require a full browser instance (not headless)
- Extensions need sequential execution (no parallelism)
- Service worker initialization takes time

Consider running only the tests you need during development:

```bash
npx playwright test block-navigation.spec.ts --headed
```
