import { test } from 'node:test';
import assert from 'node:assert/strict';
import { subtract, parseCIDR, cidrToRange, rangeToCIDRs } from '../src/core.js';

// Helper: sort an array of CIDR strings for deterministic comparison.
// We compare by numeric start address so order is stable regardless of
// string lexicography (which would put '10' before '9').
function sortedCIDRs(cidrs) {
  return [...cidrs].sort((a, b) => {
    const ra = cidrToRange(a);
    const rb = cidrToRange(b);
    if (ra.start !== rb.start) return ra.start < rb.start ? -1 : 1;
    return 0;
  });
}

// Helper: deep-equal on sorted CIDR lists.
function cidrEqual(actual, expected) {
  assert.deepEqual(sortedCIDRs(actual), sortedCIDRs(expected));
}

// --- parseCIDR ---

test('parseCIDR parses a basic IPv4 block and zeroes host bits', () => {
  const b = parseCIDR('10.1.2.3/8');
  assert.equal(b.version, 4);
  assert.equal(b.prefix, 8);
  assert.equal(b.start, 0x0a000000n); // 10.0.0.0, host bits zeroed
  assert.equal(b.end, 0x0affffffn); // 10.255.255.255
});

test('parseCIDR parses a /32 IPv4 as a single address', () => {
  const b = parseCIDR('192.168.1.5/32');
  assert.equal(b.start, 0xc0a80105n);
  assert.equal(b.end, 0xc0a80105n);
});

test('parseCIDR parses IPv6 with :: compression', () => {
  const b = parseCIDR('2001:db8::/32');
  assert.equal(b.version, 6);
  assert.equal(b.prefix, 32);
  assert.equal(b.start, 0x20010db8000000000000000000000000n);
  assert.equal(b.end, 0x20010db8ffffffffffffffffffffffffn);
});

test('parseCIDR rejects malformed input', () => {
  assert.throws(() => parseCIDR('not-a-cidr'), /prefix length/);
  assert.throws(() => parseCIDR('10.0.0.0'), /prefix length/);
  assert.throws(() => parseCIDR('10.0.0.0/33'), /too large/);
  assert.throws(() => parseCIDR('10.0.0.0/abc'), /Invalid prefix/);
  assert.throws(() => parseCIDR('10.0.0.256/24'), /out of range/);
  assert.throws(() => parseCIDR('10.0.0/24'), /Invalid IPv4/);
});

// --- rangeToCIDRs ---

test('rangeToCIDRs converts a /24 range to a single block', () => {
  const r = cidrToRange('10.0.0.0/24');
  assert.deepEqual(rangeToCIDRs(r.start, r.end, 4), ['10.0.0.0/24']);
});

test('rangeToCIDRs splits an unaligned range maximally', () => {
  // 10.0.0.1 .. 10.0.0.6 → 10.0.0.1/32, 10.0.0.2/31, 10.0.0.4/31, 10.0.0.6/32
  const r = { start: 0x0a000001n, end: 0x0a000006n };
  assert.deepEqual(rangeToCIDRs(r.start, r.end, 4), [
    '10.0.0.1/32',
    '10.0.0.2/31',
    '10.0.0.4/31',
    '10.0.0.6/32',
  ]);
});

test('rangeToCIDRs full IPv4 space is 0.0.0.0/0', () => {
  assert.deepEqual(rangeToCIDRs(0n, 0xffffffffn, 4), ['0.0.0.0/0']);
});

// --- subtract: IPv4 ---

test('subtract removes a contained block', () => {
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.0.0.128/25']),
    ['10.0.0.0/25'],
  );
});

test('subtract of identical blocks is empty', () => {
  assert.deepEqual(subtract(['10.0.0.0/24'], ['10.0.0.0/24']), []);
});

test('subtract a /32 from a /24 leaves the rest as two blocks', () => {
  // Removing 10.0.0.5/32 from 10.0.0.0/24:
  //   10.0.0.0/30 (covers .0-.3, since .4 alone would be /32+ but we need
  //   maximal blocks; actually .0-.4 minus .5...)
  // Let's compute by hand: range is 10.0.0.0..10.0.0.255 minus 10.0.0.5.
  // Holes: [10.0.0.0, 10.0.0.4] and [10.0.0.6, 10.0.0.255].
  // [10.0.0.0, 10.0.0.4] → 10.0.0.0/30, 10.0.0.4/32
  // [10.0.0.6, 10.0.0.255] → 10.0.0.6/31, 10.0.0.8/29, 10.0.0.16/28,
  //   10.0.0.32/27, 10.0.0.64/26, 10.0.0.128/25
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.0.0.5/32']),
    [
      '10.0.0.0/30',
      '10.0.0.4/32',
      '10.0.0.6/31',
      '10.0.0.8/29',
      '10.0.0.16/28',
      '10.0.0.32/27',
      '10.0.0.64/26',
      '10.0.0.128/25',
    ],
  );
});

test('subtract a non-overlapping block returns the minuend unchanged', () => {
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.1.0.0/24']),
    ['10.0.0.0/24'],
  );
});

test('subtract a block that partially overlaps the minuend', () => {
  // 10.0.0.0/24 minus 10.0.0.128/25 → 10.0.0.128/25 covers .128-.255 of the
  // .0-.255 minuend, leaving 10.0.0.0/25.
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.0.0.128/25']),
    ['10.0.0.0/25'],
  );
});

test('subtract a larger subtrahend that swallows the minuend yields empty', () => {
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.0.0.0/23']),
    [],
  );
});

test('subtract flattens overlapping minuend blocks before subtracting', () => {
  // Two overlapping minuend blocks 10.0.0.0/24 and 10.0.0.128/25 flatten to
  // [10.0.0.0, 10.0.0.255]. Removing 10.0.0.0/25 leaves 10.0.0.128/25.
  cidrEqual(
    subtract(['10.0.0.0/24', '10.0.0.128/25'], ['10.0.0.0/25']),
    ['10.0.0.128/25'],
  );
});

test('subtract with empty minuend returns empty', () => {
  assert.deepEqual(subtract([], ['10.0.0.0/24']), []);
});

test('subtract with empty subtrahend returns flattened minuend', () => {
  cidrEqual(
    subtract(['10.0.0.0/24', '10.0.0.0/24'], []),
    ['10.0.0.0/24'],
  );
});

test('subtract across multiple subtrahends leaves correct holes', () => {
  // 10.0.0.0/24 minus {10.0.0.0/30, 10.0.0.128/26}:
  //   hole 1: 10.0.0.4/30, 10.0.0.8/29, 10.0.0.16/28, 10.0.0.32/27, 10.0.0.64/26
  //   hole 2: 10.0.0.192/26
  cidrEqual(
    subtract(['10.0.0.0/24'], ['10.0.0.0/30', '10.0.0.128/26']),
    [
      '10.0.0.4/30',
      '10.0.0.8/29',
      '10.0.0.16/28',
      '10.0.0.32/27',
      '10.0.0.64/26',
      '10.0.0.192/26',
    ],
  );
});

// --- subtract: IPv6 ---

test('subtract IPv6 contained block', () => {
  cidrEqual(
    subtract(['2001:db8::/32'], ['2001:db8:8000::/33']),
    ['2001:db8::/33'],
  );
});

test('subtract IPv6 single address from /120', () => {
  // 2001:db8::/120 is 256 addresses. Removing the very last one
  // (2001:db8::ff) leaves ::0..::fe. The maximal CIDR decomposition:
  //   ::/121 (::0-::7f), ::80/122 (::80-::bf), ::c0/123 (::c0-::df),
  //   ::e0/124 (::e0-::ef), ::f0/125 (::f0-::f7), ::f8/126 (::f8-::fb),
  //   ::fc/127 (::fc-::fd), ::fe/128 (::fe).
  cidrEqual(
    subtract(['2001:db8::/120'], ['2001:db8::ff/128']),
    [
      '2001:db8::/121',
      '2001:db8::80/122',
      '2001:db8::c0/123',
      '2001:db8::e0/124',
      '2001:db8::f0/125',
      '2001:db8::f8/126',
      '2001:db8::fc/127',
      '2001:db8::fe/128',
    ],
  );
});

test('subtract rejects mixed address families', () => {
  assert.throws(
    () => subtract(['10.0.0.0/24'], ['2001:db8::/32']),
    /Cannot subtract/,
  );
});

// --- formatting ---

test('output IPv6 is canonical lowercase with maximal zero-compression', () => {
  // 2001:db8::/32 minus 2001:db8:8000::/33 → 2001:db8::/33
  const result = subtract(['2001:db8::/32'], ['2001:db8:8000::/33']);
  assert.deepEqual(result, ['2001:db8::/33']);
});

test('output IPv4 zeroed network addresses are canonical', () => {
  // Parsing 10.0.0.5/8 zeroes the host bits; subtracting nothing returns
  // the canonical 10.0.0.0/8.
  cidrEqual(subtract(['10.0.0.5/8'], []), ['10.0.0.0/8']);
});
