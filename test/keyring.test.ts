import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { runWithInput } from '../dist/lib/keyring.js';

describe('keyring child process', () => {
  test('closes stdin so the child can finish', { timeout: 2000 }, async () => {
    // `node -e` acts as a portable `cat`: it reads stdin and exits on EOF.
    const { stdout } = await runWithInput(
      process.execPath,
      ['-e', 'process.stdin.pipe(process.stdout)'],
      'hello',
    );
    assert.equal(stdout, 'hello');
  });

  test('rejects with stderr when the child fails', async () => {
    await assert.rejects(
      () =>
        runWithInput(
          process.execPath,
          ['-e', 'process.stderr.write("no keyring"); process.exit(3)'],
          '',
        ),
      /exited with code 3: no keyring/,
    );
  });
});
