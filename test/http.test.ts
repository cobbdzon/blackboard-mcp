import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar } from 'tough-cookie';

import { Session } from '../dist/auth/session.js';
import { HttpClient } from '../dist/client/http.js';

const BASE = 'https://bb.example.edu';

function client(extraHosts: string[] = []): HttpClient {
  const session = new Session(
    BASE,
    new CookieJar(),
    undefined,
    'test-agent',
    new Date('2026-01-01T00:00:00Z'),
    undefined,
    [],
  );
  return new HttpClient(session, {
    baseUrl: BASE,
    pageSize: 50,
    maxDownloadBytes: 1024 * 1024,
    allowWrites: false,
    extraHosts,
  });
}

const fileUrl = (host: string): string => `https://${host}/file.pdf`;

describe('HTTP host allowlist', () => {
  test('allows Xythos file CDN hosts', () => {
    const http = client();
    const url = http.resolve(
      fileUrl('learn-ap-southeast-1-prod-fleet02-xythos.content.blackboardcdn.com'),
    );
    assert.equal(
      url.hostname,
      'learn-ap-southeast-1-prod-fleet02-xythos.content.blackboardcdn.com',
    );
  });

  test('accepts configured host suffixes', () => {
    const http = client(['.example-cdn.com']);
    assert.doesNotThrow(() => http.resolve(fileUrl('files.example-cdn.com')));
    assert.throws(
      () => http.resolve(fileUrl('notexample-cdn.com')),
      /Refusing to send session cookies/,
    );
  });

  test('keeps exact extraHosts entries working', () => {
    const http = client(['cdn.example.net']);
    assert.doesNotThrow(() => http.resolve(fileUrl('cdn.example.net')));
  });

  test('rejects lookalike CDN hosts', () => {
    const http = client();
    assert.throws(
      () => http.resolve(fileUrl('evilblackboardcdn.com')),
      /Refusing to send session cookies/,
    );
  });
});
