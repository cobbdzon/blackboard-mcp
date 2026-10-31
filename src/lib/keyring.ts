import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { platform } from 'node:os';
import { keyfilePath, stateDir, ensureDir } from './paths.js';
import { log } from './logger.js';

const run = promisify(execFile);

const SERVICE = 'blackboard-mcp';
const ACCOUNT = 'session-encryption-key';
const KEYRING_TIMEOUT_MS = 5000;

/**
 * Runs `file` with `args`, writes `input` to stdin, then closes it.
 *
 * `execFile` has no `input` option (only `execFileSync` and `spawnSync` do).
 * Passing one is silently ignored, leaving the child with an open stdin pipe
 * that never reaches EOF. `secret-tool store` reads the secret from stdin until
 * EOF, so it would block until the timeout. This closes stdin explicitly.
 *
 * Exported for the regression test; it is not part of the package's public API.
 */
export function runWithInput(
  file: string,
  args: readonly string[],
  input: string,
  timeoutMs = KEYRING_TIMEOUT_MS,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk; });
    child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${file} exited with code ${code}: ${stderr.trim()}`));
    });
    // The child may exit before reading stdin; ignore the resulting EPIPE.
    child.stdin?.on('error', () => {});
    child.stdin?.end(input);
  });
}

/**
 * Resolves the 32-byte key used to encrypt the session at rest.
 *
 * Preference order:
 *   1. OS keychain (macOS `security`, Linux `secret-tool`). Key never touches disk.
 *   2. A 0600 keyfile under the state dir. Portable fallback.
 *
 * The fallback is deliberately not treated as a failure: it is still strictly
 * better than a plaintext session file, and it keeps the package dependency-free
 * (no native `keytar` build step, which is a common install blocker).
 */
export async function resolveKey(): Promise<Buffer> {
  const fromOs = await readFromOsKeychain();
  if (fromOs) return fromOs;

  const generated = randomBytes(32);
  if (await writeToOsKeychain(generated)) return generated;

  return readOrCreateKeyfile();
}

async function readFromOsKeychain(): Promise<Buffer | null> {
  try {
    if (platform() === 'darwin') {
      const { stdout } = await run('security', [
        'find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w',
      ]);
      const hex = stdout.trim();
      if (hex.length === 64) return Buffer.from(hex, 'hex');
      return null;
    }
    if (platform() === 'linux') {
      const { stdout } = await run('secret-tool', [
        'lookup', 'service', SERVICE, 'account', ACCOUNT,
      ], { timeout: KEYRING_TIMEOUT_MS });
      const hex = stdout.trim();
      if (hex.length === 64) return Buffer.from(hex, 'hex');
      return null;
    }
  } catch {
    // Not found, or the tool is unavailable. Fall through to the next strategy.
  }
  return null;
}

async function writeToOsKeychain(key: Buffer): Promise<boolean> {
  const hex = key.toString('hex');
  try {
    if (platform() === 'darwin') {
      await run('security', [
        'add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', hex, '-U',
      ]);
      log.debug('Stored session key in macOS keychain');
      return true;
    }
    if (platform() === 'linux') {
      await runWithInput('secret-tool', [
        'store', '--label=Blackboard MCP session key',
        'service', SERVICE, 'account', ACCOUNT,
      ], hex);
      log.debug('Stored session key in Secret Service');
      return true;
    }
  } catch {
    log.debug('OS keychain unavailable; using keyfile fallback');
  }
  return false;
}

function readOrCreateKeyfile(): Buffer {
  const path = keyfilePath();
  if (existsSync(path)) {
    const hex = readFileSync(path, 'utf8').trim();
    if (hex.length === 64) return Buffer.from(hex, 'hex');
  }
  ensureDir(stateDir());
  const key = randomBytes(32);
  writeFileSync(path, key.toString('hex'), { mode: 0o600 });
  chmodSync(path, 0o600);
  return key;
}

/** Removes the key from wherever it lives. Used by `auth logout --purge`. */
export async function deleteKey(): Promise<void> {
  try {
    if (platform() === 'darwin') {
      await run('security', ['delete-generic-password', '-s', SERVICE, '-a', ACCOUNT]);
    } else if (platform() === 'linux') {
      await run('secret-tool', ['clear', 'service', SERVICE, 'account', ACCOUNT]);
    }
  } catch {
    // Nothing stored; not an error.
  }
}
