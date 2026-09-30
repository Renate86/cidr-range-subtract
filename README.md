# CIDR Range Subtract

Removes one set of CIDR blocks (the subtrahend) from another (the minuend) and returns the remaining non-overlapping CIDR list.

```js
import { subtract, parseCIDR, cidrToRange, rangeToCIDRs } from 'cidr-range-subtract';

// Remove 10.0.0.128/25 from 10.0.0.0/24.
const remaining = subtract(['10.0.0.0/24'], ['10.0.0.128/25']);
// → ['10.0.0.0/25']

// Inspect a block's inclusive integer range.
const r = cidrToRange('2001:db8::/32');
// → { start: 42548478486261346559606547842043717632n,
//     end:   42548478486261346559606547842043717632n + ...n }
```

## Exports

- `subtract(minuend: string[], subtrahend: string[]): string[]` — the main entry point.
- `parseCIDR(cidr: string): { version, prefix, start, end }` — parse one block to a bigint range.
- `cidrToRange(cidr: string): { start, end }` — convenience wrapper returning just the inclusive integer endpoints.
- `rangeToCIDRs(start, end, version): string[]` — convert an inclusive bigint range back to a minimal CIDR list. `version` is `4` or `6`.

## Why

Computing "what's left of this network after I carve out these subnets" by hand is error-prone and the wrong shape for a spreadsheet. This library does it with bigint arithmetic and a single sweep over flattened, merged ranges — no dependencies, no WASM, no floating point.

The trade-off: everything lives in bigint, which is fine for IPv6's 128-bit space on any runtime that supports `BigInt` (Node 10+, every modern browser). The cost is that values above `2^53` cannot be round-tripped through `Number`, so the public API deals in strings (CIDR text) and bigints (the `parseCIDR` / `cidrToRange` return values) — never plain Numbers for addresses.

## Edge cases worth knowing

- **Host bits in input are silently zeroed.** `10.0.0.5/8` is treated as `10.0.0.0/8`. This matches how real routing tables behave. If you need to reject non-network addresses, validate with `parseCIDR` and compare the parsed `start` against your input.
- **Overlapping input blocks are fine.** Both the minuend and subtrahend are flattened to disjoint ranges before subtraction, so duplicates and overlaps collapse cleanly.
- **No mixed address families.** Subtracting IPv6 from IPv4 (or vice versa) throws. The version is inferred from the minuend; an empty minuend adopts the subtrahend's version.
- **IPv6 formatting is canonical.** Output uses lowercase hex with maximal `::` compression per RFC 5952, so `2001:DB8:0000:0000:0000:0000:0000:0000/32` comes back as `2001:db8::/32`.
- **Empty minuend → empty result**, regardless of the subtrahend. Empty subtrahend → the minuend returned as a minimal canonical CIDR list.
