import { decodeInput } from './decode-input';
import { parseCertificates } from './parse-certificate';
import { validateChain } from './validate-chain';
import type { AnalysisResult, DecodeIssue } from './types';

export * from './types';
export { decodeInput } from './decode-input';
export {
  detectFormat,
  extractPemBlocks,
  FORMAT_LABELS,
  readDerHeader,
  detectDerShape,
} from './detect-format';
export {
  parseCertificate,
  parseCertificates,
  buildValidity,
  CertificateParseError,
  EXPIRY_WARNING_DAYS,
  MS_PER_DAY,
} from './parse-certificate';
export { buildChain, isIssuerOf } from './build-chain';
export { validateChain } from './validate-chain';
export { certificateAsn1Tree, parseAsn1 } from './asn1-tree';
export { opensslView, OPENSSL_COMMAND } from './openssl-view';
export { certificateFingerprints, fingerprint } from './fingerprint';
export {
  canonicalDn,
  dnValue,
  parseDistinguishedName,
  renderGeneralName,
} from './names';
export * from './encoding';
export * from './oids';

export interface AnalyzeOptions {
  now?: Date;
  verifySignatures?: boolean;
}

/**
 * The one entry point the UI needs: raw input in, everything the app displays
 * out. Runs entirely in the caller's process — no network, no storage.
 */
export async function analyzeInput(
  input: string | Uint8Array,
  options: AnalyzeOptions = {},
): Promise<AnalysisResult> {
  const decode = decodeInput(input);
  const { certificates, errors } = await parseCertificates(
    decode.blocks.map((block) => block.der),
    { now: options.now },
  );

  const issues: DecodeIssue[] = [...decode.issues];
  for (const error of errors) {
    issues.push({
      severity: 'error',
      code: 'PARSE_FAILED',
      message: 'Unable to parse certificate.',
      detail: error.message,
    });
  }

  const chain = await validateChain(certificates, {
    now: options.now,
    verifySignatures: options.verifySignatures,
  });

  return { decode, chain, issues };
}
