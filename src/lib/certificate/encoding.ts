/** Small byte/text helpers shared by the decoder and the parser. */

const BASE64_ALPHABET = /^[A-Za-z0-9+/=\s]*$/;

export function toHex(bytes: Uint8Array, separator = ''): string {
  const out: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i].toString(16).padStart(2, '0').toUpperCase();
  }
  return out.join(separator);
}

export function toColonHex(bytes: Uint8Array): string {
  return toHex(bytes, ':');
}

/** Wraps a long string at `width` characters, for hex dumps and base64. */
export function wrap(value: string, width = 64): string {
  const lines: string[] = [];
  for (let i = 0; i < value.length; i += width) {
    lines.push(value.slice(i, i + width));
  }
  return lines.join('\n');
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  if (typeof btoa === 'function') return btoa(binary);
  return Buffer.from(bytes).toString('base64');
}

export function base64ToBytes(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, '');
  const binary =
    typeof atob === 'function'
      ? atob(clean)
      : Buffer.from(clean, 'base64').toString('binary');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function isProbablyBase64(value: string): boolean {
  const clean = value.replace(/\s+/g, '');
  if (clean.length < 16) return false;
  return BASE64_ALPHABET.test(value) && /^[A-Za-z0-9+/]+={0,2}$/.test(clean);
}

/** Characters that are valid base64 but not part of the alphabet. */
export function invalidBase64Characters(value: string): string[] {
  const bad = new Set<string>();
  for (const ch of value.replace(/\s+/g, '')) {
    if (!/[A-Za-z0-9+/=]/.test(ch)) bad.add(ch);
  }
  return [...bad];
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function toPem(der: Uint8Array, label = 'CERTIFICATE'): string {
  return [
    `-----BEGIN ${label}-----`,
    wrap(bytesToBase64(der), 64),
    `-----END ${label}-----`,
  ].join('\n');
}

export function bytesEqual(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Big-endian bytes → decimal string, for serial numbers. */
export function bytesToDecimal(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value.toString(10);
}

/** Renders an IPv4 (4 bytes) or IPv6 (16 bytes) address from SAN octets. */
export function bytesToIpAddress(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  if (bytes.length === 8) {
    // IPv4 address + mask, as used in name constraints.
    return `${Array.from(bytes.subarray(0, 4)).join('.')}/${Array.from(
      bytes.subarray(4),
    ).join('.')}`;
  }
  if (bytes.length === 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return compressIpv6(groups);
  }
  if (bytes.length === 32) {
    return `${bytesToIpAddress(bytes.subarray(0, 16))}/${bytesToIpAddress(
      bytes.subarray(16),
    )}`;
  }
  return toColonHex(bytes);
}

function compressIpv6(groups: string[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let start = -1;
  let length = 0;
  for (let i = 0; i <= groups.length; i++) {
    if (i < groups.length && groups[i] === '0') {
      if (start < 0) start = i;
      length++;
    } else {
      if (length > bestLength) {
        bestLength = length;
        bestStart = start;
      }
      start = -1;
      length = 0;
    }
  }
  if (bestLength < 2) return groups.join(':');
  return `${groups.slice(0, bestStart).join(':')}::${groups
    .slice(bestStart + bestLength)
    .join(':')}`;
}

/** Formats a Date as `YYYY-MM-DD HH:mm:ss UTC`. */
export function formatUtc(date: Date): string {
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
  );
}

/** Formats a Date in the viewer's own timezone. */
export function formatLocal(date: Date): string {
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  const pad = (n: number) => String(n).padStart(2, '0');
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const abs = Math.abs(offsetMinutes);
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ` +
    `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
  );
}

/** `openssl x509 -text` style date: `Jan 12 00:00:00 2026 GMT`. */
export function formatOpenSslDate(date: Date): string {
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];
  const pad = (n: number) => String(n).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, ' ');
  return (
    `${months[date.getUTCMonth()]} ${day} ${pad(date.getUTCHours())}:` +
    `${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} ` +
    `${date.getUTCFullYear()} GMT`
  );
}
