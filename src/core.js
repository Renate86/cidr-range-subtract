/**
 * CIDR block arithmetic for IPv4 and IPv6.
 *
 * The whole library operates on bigints internally. CIDR blocks are converted
 * to inclusive [start, end] integer ranges, subtracted as integer intervals,
 * and the remaining intervals are converted back to minimal CIDR lists.
 *
 * Design decisions (stated plainly so the tests and the reader agree):
 *
 * 1. Only IPv4 and IPv6. No hybrid parsing, no EUI-64, no zone IDs.
 * 2. Input CIDRs may overlap; the subtractor handles overlap by flattening
 *    both the minuend and subtrahend into disjoint ranges first.
 * 3. Output is always minimal: no CIDR in the result is adjacent to or
 *    contained in another, and every CIDR is the largest block that fits
 *    the hole it covers.
 * 4. Addresses are returned as lowercase strings (IPv6 uses lowercase hex
 *    with maximal zero-compression), matching Node's canonical formatting.
 * 5. parseCIDR throws on anything malformed — bad prefix lengths, non-numeric
 *    octets, out-of-range values, missing '/'. The error type is Error.
 */

/** @typedef {{ start: bigint, end: bigint }} Range */
/** @typedef {{ version: 4 | 6, prefix: number, start: bigint, end: bigint }} Block */

const IPV4_BITS = 32n;
const IPV6_BITS = 128n;

/**
 * Parse a dotted-quad IPv4 address into a bigint.
 * @param {string} s
 * @returns {bigint}
 */
function parseIPv4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${s}`);
  }
  let result = 0n;
  for (const part of parts) {
    if (!/^[0-9]+$/.test(part)) {
      throw new Error(`Invalid IPv4 octet: ${part}`);
    }
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error(`IPv4 octet out of range: ${part}`);
    }
    result = (result << 8n) | BigInt(n);
  }
  return result;
}

/**
 * Parse a colon-separated IPv6 address into a bigint.
 * Handles :: expansion and dotted-quad tails (the last 32 bits written as
 * a.b.c.d), which the spec permits and real configurations occasionally use.
 * @param {string} s
 * @returns {bigint}
 */
function parseIPv6(s) {
  // Dotted-quad suffix: if the address contains a '.', the final group is
  // an embedded IPv4. We split it off and parse it as four 16-bit halves.
  const dotIndex = s.lastIndexOf('.');
  if (dotIndex !== -1) {
    // Find the IPv4 portion: everything from the last ':' before the dot.
    const colonBeforeDot = s.lastIndexOf(':', dotIndex);
    if (colonBeforeDot === -1) {
      throw new Error(`Invalid IPv6 address: ${s}`);
    }
    const v4Part = s.slice(colonBeforeDot + 1);
    const v4Val = parseIPv4(v4Part);
    const hi = v4Val >> 16n;
    const lo = v4Val & 0xffffn;
    const head = s.slice(0, colonBeforeDot + 1);
    s = head + hi.toString(16) + ':' + lo.toString(16);
  }

  // Split on '::' to find how many groups were omitted.
  const doubleColon = s.indexOf('::');
  let groups;
  let fill = 0;
  if (doubleColon !== -1) {
    if (s.indexOf('::', doubleColon + 1) !== -1) {
      throw new Error(`Invalid IPv6 address (multiple '::'): ${s}`);
    }
    const left = s.slice(0, doubleColon);
    const right = s.slice(doubleColon + 2);
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const present = leftParts.length + rightParts.length;
    if (present > 8) {
      throw new Error(`Invalid IPv6 address (too many groups): ${s}`);
    }
    fill = 8 - present;
    groups = [...leftParts, ...Array(fill).fill('0'), ...rightParts];
  } else {
    groups = s.split(':');
    if (groups.length !== 8) {
      throw new Error(`Invalid IPv6 address (need 8 groups): ${s}`);
    }
  }

  let result = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
      throw new Error(`Invalid IPv6 group: ${g}`);
    }
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
}

/**
 * Format a bigint in the range [0, 2^32) as a dotted-quad string.
 * @param {bigint} v
 * @returns {string}
 */
function formatIPv4(v) {
  const mask = 0xffn;
  const a = (v >> 24n) & mask;
  const b = (v >> 16n) & mask;
  const c = (v >> 8n) & mask;
  const d = v & mask;
  return `${a}.${b}.${c}.${d}`;
}

/**
 * Format a 128-bit bigint as a canonical lowercase IPv6 string with maximal
 * zero-compression. We pick the longest run of zero groups to compress; ties
 * go to the leftmost run, per RFC 5952.
 * @param {bigint} v
 * @returns {string}
 */
function formatIPv6(v) {
  const groups = [];
  const mask = 0xffffn;
  for (let i = 7; i >= 0; i--) {
    groups.push(Number((v >> BigInt(i * 16)) & mask));
  }
  // Find the longest run of zero 16-bit groups. Leftmost wins on ties.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  // RFC 5952: only compress runs of length >= 2.
  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }
  const left = groups.slice(0, bestStart).map((g) => g.toString(16));
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16));
  const leftStr = left.join(':');
  const rightStr = right.join(':');
  if (left.length === 0 && right.length === 0) return '::';
  if (left.length === 0) return '::' + rightStr;
  if (right.length === 0) return leftStr + '::';
  return leftStr + '::' + rightStr;
}

/**
 * Parse a CIDR string like "10.0.0.0/8" or "2001:db8::/32".
 * Returns the block's version, prefix length, and inclusive [start, end] range.
 * @param {string} cidr
 * @returns {Block}
 */
export function parseCIDR(cidr) {
  if (typeof cidr !== 'string') {
    throw new Error(`CIDR must be a string, got ${typeof cidr}`);
  }
  const slash = cidr.indexOf('/');
  if (slash === -1) {
    throw new Error(`CIDR missing prefix length: ${cidr}`);
  }
  const addrStr = cidr.slice(0, slash);
  const prefixStr = cidr.slice(slash + 1);
  if (!/^[0-9]+$/.test(prefixStr)) {
    throw new Error(`Invalid prefix length: ${prefixStr}`);
  }
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0) {
    throw new Error(`Invalid prefix length: ${prefixStr}`);
  }

  const hasDot = addrStr.includes('.');
  const hasColon = addrStr.includes(':');

  let version, bits, start;
  if (hasColon) {
    version = 6;
    bits = IPV6_BITS;
    start = parseIPv6(addrStr);
  } else if (hasDot) {
    version = 4;
    bits = IPV4_BITS;
    start = parseIPv4(addrStr);
  } else {
    throw new Error(`Unrecognized address format: ${addrStr}`);
  }

  if (prefix > Number(bits)) {
    throw new Error(`Prefix /${prefix} too large for IPv${version}`);
  }

  const prefixBig = BigInt(prefix);
  // Host bits are the low (bits - prefix) bits. Mask them to zero so the
  // block start is the network address, regardless of what the caller wrote.
  const hostBits = bits - prefixBig;
  const networkMask = (bits === IPV4_BITS ? 1n : 1n) << bits;
  // Equivalent: mask of prefix leading 1s = ((1n << prefixBig) - 1n) << hostBits.
  const mask = ((1n << prefixBig) - 1n) << hostBits;
  const network = start & mask;
  const broadcast = network | ((1n << hostBits) - 1n);
  return { version, prefix, start: network, end: broadcast };
}

/**
 * Convert a CIDR string to an inclusive [start, end] integer range.
 * Convenience wrapper around parseCIDR for callers who only want the numbers.
 * @param {string} cidr
 * @returns {Range}
 */
export function cidrToRange(cidr) {
  const b = parseCIDR(cidr);
  return { start: b.start, end: b.end };
}

/**
 * Convert a [start, end] inclusive integer range back to a minimal list of
 * CIDR blocks. The algorithm walks the range from low to high, emitting the
 * largest block whose network address is the current position and whose
 * broadcast does not exceed end, then advancing past it.
 *
 * The key invariant for "largest block at position n": a block of width w
 * (2^w addresses) starting at n requires n % (2^w) == 0. So we want the
 * largest w such that:
 *   - n is a multiple of 2^w (alignment), AND
 *   - n + 2^w - 1 <= end (the block fits inside the remaining range), AND
 *   - for IPv4, w <= 32; for IPv6, w <= 128 (can't exceed the address space).
 *
 * @param {bigint} start
 * @param {bigint} end
 * @param {4 | 6} version
 * @returns {string[]}
 */
export function rangeToCIDRs(start, end, version) {
  if (start > end) {
    throw new Error(`Invalid range: start ${start} > end ${end}`);
  }
  const bits = version === 4 ? IPV4_BITS : IPV6_BITS;
  const format = version === 4 ? formatIPv4 : formatIPv6;
  const result = [];
  let current = start;
  while (current <= end) {
    // Largest block width w such that current is aligned to 2^w and the
    // block fits. Alignment: w is bounded by the number of trailing zero
    // bits in current (or the remaining address-space width, whichever is
    // smaller). Then we shrink w until current + 2^w - 1 <= end.
    let w = 0n;
    // Determine the max alignment width from trailing zeros of current.
    // current === 0 is a special case (all bits zero → max width).
    let maxAlign;
    if (current === 0n) {
      maxAlign = bits;
    } else {
      // count trailing zero bits
      let c = current;
      let zeros = 0n;
      while ((c & 1n) === 0n && zeros < bits) {
        zeros++;
        c >>= 1n;
      }
      maxAlign = zeros;
    }
    w = maxAlign;
    // Shrink w until the block of size 2^w fits within [current, end].
    // Block size = 1n << w; broadcast = current + size - 1.
    while (w > 0n && current + (1n << w) - 1n > end) {
      w--;
    }
    // w is now the largest width that is both aligned and fits.
    const size = 1n << w;
    const broadcast = current + size - 1n;
    const prefix = Number(bits - w);
    result.push(`${format(current)}/${prefix}`);
    current = broadcast + 1n;
  }
  return result;
}

/**
 * Merge a list of inclusive ranges into a minimal set of disjoint, sorted,
 * non-adjacent ranges. Adjacent ranges (a.end + 1 === b.start) are coalesced
 * so the downstream CIDR expansion produces maximal blocks.
 * @param {Range[]} ranges
 * @returns {Range[]}
 */
function mergeRanges(ranges) {
  if (ranges.length === 0) return [];
  const sorted = [...ranges].sort((a, b) =>
    a.start < b.start ? -1 : a.start > b.start ? 1 : 0,
  );
  const merged = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    const r = sorted[i];
    const last = merged[merged.length - 1];
    // Overlap or adjacency → merge. Adjacency matters here because two
    // touching holes should become one CIDR-able range.
    if (r.start <= last.end + 1n) {
      if (r.end > last.end) last.end = r.end;
    } else {
      merged.push({ start: r.start, end: r.end });
    }
  }
  return merged;
}

/**
 * Subtract a list of CIDR blocks (the subtrahend) from a list of CIDR blocks
 * (the minuend) and return the remaining non-overlapping CIDR list.
 *
 * Both inputs are flattened to disjoint ranges first, so overlapping input
 * blocks are fine. The result is minimal: adjacent holes are merged before
 * CIDR expansion, so the output never contains two CIDRs that could be one.
 *
 * IPv4 and IPv6 must not be mixed in the same call; the function will throw
 * if the two lists disagree on address family. An empty minuend yields an
 * empty result; an empty subtrahend returns the minuend unchanged.
 *
 * @param {string[]} minuendCidrs
 * @param {string[]} subtrahendCidrs
 * @returns {string[]}
 */
export function subtract(minuendCidrs, subtrahendCidrs) {
  if (!Array.isArray(minuendCidrs) || !Array.isArray(subtrahendCidrs)) {
    throw new Error('Both arguments must be arrays of CIDR strings');
  }

  if (minuendCidrs.length === 0) return [];
  // Empty subtrahend: return minuend, flattened to canonical minimal CIDRs.
  // We still parse+flatten so overlapping minuend blocks come back clean.

  let version;
  const minuendRanges = [];
  for (const c of minuendCidrs) {
    const b = parseCIDR(c);
    if (version === undefined) version = b.version;
    else if (version !== b.version) {
      throw new Error('Cannot mix IPv4 and IPv6 in minuend');
    }
    minuendRanges.push({ start: b.start, end: b.end });
  }

  const subtrahendRanges = [];
  for (const c of subtrahendCidrs) {
    const b = parseCIDR(c);
    if (version === undefined) {
      // Minuend was empty but subtrahend is not — we still need a version
      // to format the (empty) result consistently. In practice the result
      // is empty either way, so we just adopt the subtrahend's version.
      version = b.version;
    } else if (version !== b.version) {
      throw new Error(`Cannot subtract IPv${b.version} from IPv${version}`);
    }
    subtrahendRanges.push({ start: b.start, end: b.end });
  }

  const mergedMinuend = mergeRanges(minuendRanges);
  const mergedSubtrahend = mergeRanges(subtrahendRanges);

  // Walk both lists, emitting the parts of each minuend range not covered
  // by any subtrahend range.
  /** @type {Range[]} */
  const holes = [];
  let si = 0; // subtrahend cursor
  for (const m of mergedMinuend) {
    let lo = m.start;
    while (si < mergedSubtrahend.length) {
      const s = mergedSubtrahend[si];
      // Subtrahend entirely before this minuend segment → skip it.
      if (s.end < lo) {
        si++;
        continue;
      }
      // Subtrahend entirely after this minuend segment → done with segment.
      if (s.start > m.end) break;
      // Overlap. Emit [lo, s.start - 1] if non-empty.
      if (s.start > lo) {
        holes.push({ start: lo, end: s.start - 1n });
      }
      // Advance lo past the subtrahend, or past the minuend if the
      // subtrahend covers the rest of it.
      if (s.end >= m.end) {
        lo = m.end + 1n; // segment fully consumed
        break;
      }
      lo = s.end + 1n;
      si++;
    }
    if (lo <= m.end) {
      holes.push({ start: lo, end: m.end });
    }
  }

  const mergedHoles = mergeRanges(holes);
  if (version === undefined) {
    // Both lists empty. Nothing to format.
    return [];
  }
  /** @type {string[]} */
  const out = [];
  for (const h of mergedHoles) {
    for (const cidr of rangeToCIDRs(h.start, h.end, version)) {
      out.push(cidr);
    }
  }
  return out;
}
