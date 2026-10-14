import type * as asn1js from 'asn1js';
import {
  AuthenticatedSafe,
  CertBag,
  EncryptedData,
  PBES2Params,
  PFX,
  PKCS8ShroudedKeyBag,
  PrivateKeyInfo,
  SafeContents,
  getCrypto,
  id_CertBag_X509Certificate,
  id_ContentType_Data,
  id_ContentType_EncryptedData,
  id_ContentType_EnvelopedData,
} from 'pkijs';

import type { DecodeIssue, DecodeResult } from './types';
import { toPem, utf8ToBytes } from './encoding';

const OID_PBES2 = '1.2.840.113549.1.5.13';

/** Ciphers WebCrypto can run inside PBES2. */
const PBES2_CIPHERS: Record<string, string> = {
  '2.16.840.1.101.3.4.1.2': 'AES-128-CBC',
  '2.16.840.1.101.3.4.1.22': 'AES-192-CBC',
  '2.16.840.1.101.3.4.1.42': 'AES-256-CBC',
};

/** Names for the encryption schemes we recognise but cannot decrypt (yet). */
const UNSUPPORTED_SCHEMES: Record<string, string> = {
  '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
  '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
  '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.4': 'pbeWithSHAAnd2-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.5': 'pbeWithSHAAnd128BitRC2-CBC',
  '1.2.840.113549.1.12.1.6': 'pbeWithSHAAnd40BitRC2-CBC',
  '1.2.840.113549.1.5.3': 'pbeWithMD5AndDES-CBC',
  '1.2.840.113549.1.5.10': 'pbeWithSHA1AndDES-CBC',
  '1.2.840.113549.1.3.7': 'DES-EDE3-CBC',
  '1.3.14.3.2.7': 'DES-CBC',
  '1.2.840.113549.1.5.14': 'PBMAC1',
};

const CONVERT_HINT =
  'Export the certificates with OpenSSL instead: ' +
  'openssl pkcs12 -in store.pfx -nokeys -out certs.pem ' +
  '(add -legacy on OpenSSL 3 for older files).';

type MacStatus = 'ok' | 'failed' | 'absent' | 'unsupported';

export interface Pkcs12Contents {
  /** DER of every X.509 certificate that could be read. */
  certificates: Uint8Array[];
  issues: DecodeIssue[];
  /** True when an unencrypted private key was found. */
  containsPrivateKey: boolean;
  /** True when a (different) password would reveal or verify more. */
  passwordRequired: boolean;
}

class Collector implements Pkcs12Contents {
  readonly certificates: Uint8Array[] = [];
  readonly issues: DecodeIssue[] = [];
  containsPrivateKey = false;
  passwordRequired = false;
  encryptedKeys = 0;
  /** Encrypted safes we could have opened with the right password. */
  locked = 0;
  readonly unsupported = new Set<string>();

  issue(
    severity: DecodeIssue['severity'],
    code: DecodeIssue['code'],
    message: string,
    detail?: string,
  ) {
    this.issues.push({ severity, code, message, detail });
  }
}

/**
 * Opens a PKCS#12 / PFX container and pulls out its certificates.
 *
 * Supports password integrity (HMAC with the PKCS#12 KDF), unencrypted safes
 * and PBES2-encrypted safes (PBKDF2 + AES-CBC, the OpenSSL 3 default). The
 * legacy RC2 / 3DES schemes are reported, not decrypted. Private keys are
 * never decrypted: they are only counted, so a key cannot leak into the page.
 *
 * Wrong or missing passwords are reported as issues, never thrown.
 */
export async function decodePkcs12(
  der: Uint8Array,
  password = '',
): Promise<Pkcs12Contents> {
  const out = new Collector();

  let pfx: PFX;
  let authSafe: AuthenticatedSafe;
  let authSafeBytes: ArrayBuffer;
  try {
    pfx = PFX.fromBER(copy(der));
    if (pfx.authSafe.contentType !== id_ContentType_Data) {
      out.issue(
        'error',
        'PKCS12_UNSUPPORTED',
        'This PFX uses public-key integrity, which is not supported.',
        CONVERT_HINT,
      );
      return out;
    }
    authSafeBytes = (pfx.authSafe.content as asn1js.OctetString).getValue();
    authSafe = AuthenticatedSafe.fromBER(authSafeBytes);
  } catch (error) {
    out.issue(
      'error',
      'PARSE_FAILED',
      'Unable to read the PKCS#12 container.',
      error instanceof Error ? error.message : undefined,
    );
    return out;
  }

  const passwordBytes = utf8ToBytes(password).slice().buffer as ArrayBuffer;
  const mac = await verifyMac(pfx, authSafeBytes, passwordBytes, out);

  for (const content of authSafe.safeContents) {
    switch (content.contentType) {
      case id_ContentType_Data: {
        const bytes = (content.content as asn1js.OctetString).getValue();
        readSafeContents(SafeContents.fromBER(bytes), out);
        break;
      }
      case id_ContentType_EncryptedData: {
        const encrypted = new EncryptedData({ schema: content.content });
        const unsupported = unsupportedScheme(encrypted);
        if (unsupported) {
          out.unsupported.add(unsupported);
          break;
        }
        // A failed MAC already proves the password wrong; decrypting would
        // only produce garbage.
        if (mac === 'failed') {
          out.locked++;
          break;
        }
        try {
          const plain = await encrypted.decrypt({ password: passwordBytes });
          readSafeContents(SafeContents.fromBER(plain), out);
        } catch {
          out.locked++;
        }
        break;
      }
      case id_ContentType_EnvelopedData:
        out.unsupported.add('public-key encryption (EnvelopedData)');
        break;
      default:
        out.unsupported.add(content.contentType);
    }
  }

  report(out, mac, password);
  return out;
}

async function verifyMac(
  pfx: PFX,
  authSafeBytes: ArrayBuffer,
  password: ArrayBuffer,
  out: Collector,
): Promise<MacStatus> {
  const macData = pfx.macData;
  if (!macData) {
    out.issue(
      'info',
      'PKCS12_NO_MAC',
      'This PFX has no integrity check.',
      'It carries no MAC, so modifications to the file cannot be detected.',
    );
    return 'absent';
  }

  const crypto = getCrypto(true);
  const oid = macData.mac.digestAlgorithm.algorithmId;
  try {
    // Throws for anything but SHA-1 / SHA-2, including PBMAC1.
    const hash = crypto.getAlgorithmByOID(oid, true);
    const ok = await crypto.verifyDataStampedWithPassword({
      password,
      hashAlgorithm: hash.name,
      salt: copy(macData.macSalt.valueBlock.valueHexView),
      iterationCount: macData.iterations || 1,
      contentToVerify: authSafeBytes,
      signatureToVerify: copy(macData.mac.digest.valueBlock.valueHexView),
    });
    return ok ? 'ok' : 'failed';
  } catch {
    out.issue(
      'warning',
      'PKCS12_UNSUPPORTED',
      'The integrity check of this PFX could not be verified.',
      `Its MAC uses ${UNSUPPORTED_SCHEMES[oid] ?? oid}, which is not supported, ` +
        'so the contents were read without checking them.',
    );
    return 'unsupported';
  }
}

/** The scheme's name when we cannot decrypt it, undefined when we can. */
function unsupportedScheme(encrypted: EncryptedData): string | undefined {
  const algorithm = encrypted.encryptedContentInfo.contentEncryptionAlgorithm;
  if (algorithm.algorithmId !== OID_PBES2) {
    return UNSUPPORTED_SCHEMES[algorithm.algorithmId] ?? algorithm.algorithmId;
  }
  try {
    const params = new PBES2Params({ schema: algorithm.algorithmParams });
    const cipher = params.encryptionScheme.algorithmId;
    if (PBES2_CIPHERS[cipher]) return undefined;
    return `PBES2 with ${UNSUPPORTED_SCHEMES[cipher] ?? cipher}`;
  } catch {
    return 'PBES2 (malformed parameters)';
  }
}

function readSafeContents(contents: SafeContents, out: Collector): void {
  for (const bag of contents.safeBags) {
    const value = bag.bagValue;
    if (value instanceof CertBag) {
      if (value.certId === id_CertBag_X509Certificate) {
        const certValue = value.certValue as asn1js.OctetString;
        out.certificates.push(certValue.valueBlock.valueHexView.slice());
      }
    } else if (value instanceof PKCS8ShroudedKeyBag) {
      out.encryptedKeys++;
    } else if (value instanceof PrivateKeyInfo) {
      out.containsPrivateKey = true;
    } else if (value instanceof SafeContents) {
      readSafeContents(value, out);
    }
  }
}

function report(out: Collector, mac: MacStatus, password: string): void {
  const decryptionFailed = out.locked > 0;
  // A failed MAC on a file whose encrypted parts we cannot open anyway is not
  // worth a password prompt — the unsupported scheme is the real blocker.
  const macBlocks = mac === 'failed' && out.unsupported.size === 0;

  if (macBlocks || decryptionFailed) {
    out.passwordRequired = true;
    const visible =
      out.certificates.length > 0
        ? ` ${out.certificates.length} certificate(s) stored unencrypted are shown, ` +
          'but the file has not been verified.'
        : '';
    if (password) {
      out.issue(
        'error',
        'PKCS12_WRONG_PASSWORD',
        'Incorrect PFX password.',
        (mac === 'failed'
          ? 'The integrity check (MAC) failed with this password.'
          : 'The encrypted contents could not be decrypted with this password.') + visible,
      );
    } else {
      out.issue(
        'warning',
        'PKCS12_PASSWORD_REQUIRED',
        'This PFX is password-protected.',
        'Enter its password to verify the file and decrypt the certificates. ' +
          'It is used only in this tab and never stored.' +
          visible,
      );
    }
  }

  if (out.unsupported.size > 0) {
    out.issue(
      'error',
      'PKCS12_UNSUPPORTED',
      `This PFX is encrypted with ${[...out.unsupported].join(', ')}, which is not supported yet.`,
      CONVERT_HINT,
    );
  }

  if (out.containsPrivateKey) {
    out.issue(
      'warning',
      'PRIVATE_KEY_DETECTED',
      'This PFX holds an unencrypted private key.',
      'It was neither uploaded nor stored, but anyone with this file can use the key.',
    );
  }

  if (out.encryptedKeys > 0) {
    out.issue(
      'info',
      'PKCS12_ENCRYPTED_KEY',
      out.encryptedKeys === 1
        ? 'The PFX also holds an encrypted private key.'
        : `The PFX also holds ${out.encryptedKeys} encrypted private keys.`,
      'Keys are left encrypted — this page never decrypts or reads them.',
    );
  }

  if (
    out.certificates.length === 0 &&
    !out.passwordRequired &&
    !out.issues.some((issue) => issue.severity === 'error')
  ) {
    out.issue('error', 'NO_CERTIFICATE_FOUND', 'The PFX contains no certificates.');
  }
}

/**
 * Completes a decode result that stopped at a PKCS#12 container: decodes the
 * container with the password and merges what it holds into the result.
 */
export async function openPkcs12(
  decode: DecodeResult,
  password?: string,
): Promise<DecodeResult> {
  if (!decode.pkcs12) return decode;
  const contents = await decodePkcs12(decode.pkcs12, password);
  return {
    ...decode,
    blocks: [
      ...decode.blocks,
      ...contents.certificates.map((der) => ({ der, pem: toPem(der), via: 'pkcs12' as const })),
    ],
    issues: [...decode.issues, ...contents.issues],
    containsPrivateKey: decode.containsPrivateKey || contents.containsPrivateKey,
    passwordRequired: contents.passwordRequired,
  };
}

/** pkijs wants a standalone ArrayBuffer. */
function copy(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}
