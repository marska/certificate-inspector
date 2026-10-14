import {
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  SignedData,
} from 'pkijs';
import { describe, expect, it } from 'vitest';

import { analyzeInput } from '../src/lib/certificate';
import { decodeInput } from '../src/lib/certificate/decode-input';
import { detectDerShape } from '../src/lib/certificate/detect-format';
import { bytesToBase64, toPem } from '../src/lib/certificate/encoding';
import { NOW, fixtures } from './fixtures';

/** Wraps certificates in a degenerate PKCS#7 SignedData, as `.p7b` files do. */
function makePkcs7(...ders: Uint8Array[]): Uint8Array {
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
    }),
    certificates: ders.map((der) =>
      Certificate.fromBER(der.slice().buffer as ArrayBuffer),
    ),
  });
  signedData.digestAlgorithms = [];
  signedData.signerInfos = [];

  const contentInfo = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: signedData.toSchema(true),
  });

  return new Uint8Array(contentInfo.toSchema().toBER(false));
}

describe('PKCS#7 bundles', () => {
  it('is recognised by shape', async () => {
    const { leaf, intermediate } = await fixtures();
    const p7b = makePkcs7(leaf.der, intermediate.der);
    expect(detectDerShape(p7b)).toBe('pkcs7');
  });

  it('extracts every certificate from binary DER', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const result = decodeInput(makePkcs7(leaf.der, intermediate.der, root.der));

    expect(result.detectedFormat).toBe('pkcs7');
    expect(result.blocks).toHaveLength(3);
    expect(result.issues).toEqual([]);
  });

  it('extracts certificates from a PEM-armoured PKCS#7 block', async () => {
    const { leaf, intermediate } = await fixtures();
    const pem = toPem(makePkcs7(leaf.der, intermediate.der), 'PKCS7');
    const result = decodeInput(pem);

    expect(result.blocks).toHaveLength(2);
  });

  it('extracts certificates from base64 PKCS#7', async () => {
    const { leaf, intermediate } = await fixtures();
    const result = decodeInput(bytesToBase64(makePkcs7(leaf.der, intermediate.der)));

    expect(result.blocks).toHaveLength(2);
  });

  it('builds a chain from a PKCS#7 bundle end to end', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const { chain } = await analyzeInput(makePkcs7(leaf.der, intermediate.der, root.der), {
      now: NOW,
    });

    expect(chain.certificates.map((c) => c.role)).toEqual([
      'leaf',
      'intermediate',
      'root',
    ]);
    expect(chain.cryptographicStatus).toBe('valid');
  });
});
