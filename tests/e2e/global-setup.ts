import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export default function globalSetup() {
  // A build is a finite task, so it belongs in setup rather than webServer.
  execFileSync('pnpm', ['run', 'build:all'], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)),
    stdio: 'inherit',
  });
}
