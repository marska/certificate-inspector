/**
 * OID dictionaries. Everything the UI shows as a friendly name resolves here,
 * and anything unknown falls back to the raw dotted number so the user is
 * never left staring at a blank field.
 */

/** Distinguished name attribute types. */
export const DN_OIDS: Record<string, { short: string; long: string }> = {
  '2.5.4.3': { short: 'CN', long: 'Common Name' },
  '2.5.4.4': { short: 'SN', long: 'Surname' },
  '2.5.4.5': { short: 'serialNumber', long: 'Serial Number' },
  '2.5.4.6': { short: 'C', long: 'Country' },
  '2.5.4.7': { short: 'L', long: 'Locality' },
  '2.5.4.8': { short: 'ST', long: 'State / Province' },
  '2.5.4.9': { short: 'STREET', long: 'Street Address' },
  '2.5.4.10': { short: 'O', long: 'Organization' },
  '2.5.4.11': { short: 'OU', long: 'Organizational Unit' },
  '2.5.4.12': { short: 'title', long: 'Title' },
  '2.5.4.13': { short: 'description', long: 'Description' },
  '2.5.4.15': { short: 'businessCategory', long: 'Business Category' },
  '2.5.4.17': { short: 'postalCode', long: 'Postal Code' },
  '2.5.4.20': { short: 'telephoneNumber', long: 'Telephone Number' },
  '2.5.4.42': { short: 'GN', long: 'Given Name' },
  '2.5.4.43': { short: 'initials', long: 'Initials' },
  '2.5.4.44': { short: 'generationQualifier', long: 'Generation Qualifier' },
  '2.5.4.45': { short: 'x500UniqueIdentifier', long: 'X500 Unique Identifier' },
  '2.5.4.46': { short: 'dnQualifier', long: 'DN Qualifier' },
  '2.5.4.65': { short: 'pseudonym', long: 'Pseudonym' },
  '2.5.4.97': { short: 'organizationIdentifier', long: 'Organization Identifier' },
  '1.2.840.113549.1.9.1': { short: 'E', long: 'Email Address' },
  '0.9.2342.19200300.100.1.1': { short: 'UID', long: 'User ID' },
  '0.9.2342.19200300.100.1.25': { short: 'DC', long: 'Domain Component' },
  '1.3.6.1.4.1.311.60.2.1.1': {
    short: 'jurisdictionL',
    long: 'Jurisdiction Locality',
  },
  '1.3.6.1.4.1.311.60.2.1.2': {
    short: 'jurisdictionST',
    long: 'Jurisdiction State',
  },
  '1.3.6.1.4.1.311.60.2.1.3': {
    short: 'jurisdictionC',
    long: 'Jurisdiction Country',
  },
};

/** Signature algorithms → { name, hash }. */
export const SIGNATURE_OIDS: Record<string, { name: string; hash?: string }> = {
  '1.2.840.113549.1.1.2': { name: 'md2WithRSAEncryption', hash: 'MD2' },
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'MD5' },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'SHA-1' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS' },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'SHA-512' },
  '1.2.840.113549.1.1.14': { name: 'sha224WithRSAEncryption', hash: 'SHA-224' },
  '1.2.840.10040.4.3': { name: 'dsaWithSha1', hash: 'SHA-1' },
  '2.16.840.1.101.3.4.3.1': { name: 'dsaWithSha224', hash: 'SHA-224' },
  '2.16.840.1.101.3.4.3.2': { name: 'dsaWithSha256', hash: 'SHA-256' },
  '1.2.840.10045.4.1': { name: 'ecdsaWithSHA1', hash: 'SHA-1' },
  '1.2.840.10045.4.3.1': { name: 'ecdsaWithSHA224', hash: 'SHA-224' },
  '1.2.840.10045.4.3.2': { name: 'ecdsaWithSHA256', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsaWithSHA384', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsaWithSHA512', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', hash: 'SHA-512' },
  '1.3.101.113': { name: 'Ed448', hash: 'SHAKE256' },
  '2.16.840.1.101.3.4.3.13': { name: 'id-RSASSA-PKCS1-v1_5-with-SHA3-256', hash: 'SHA3-256' },
};

/** Hash algorithms, used for RSASSA-PSS parameters and digest display. */
export const HASH_OIDS: Record<string, string> = {
  '1.2.840.113549.2.2': 'MD2',
  '1.2.840.113549.2.5': 'MD5',
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
  '2.16.840.1.101.3.4.2.4': 'SHA-224',
  '2.16.840.1.101.3.4.2.7': 'SHA3-224',
  '2.16.840.1.101.3.4.2.8': 'SHA3-256',
  '2.16.840.1.101.3.4.2.9': 'SHA3-384',
  '2.16.840.1.101.3.4.2.10': 'SHA3-512',
};

/** Public key algorithms. */
export const PUBLIC_KEY_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10040.4.1': 'DSA',
  '1.2.840.10045.2.1': 'ECDSA',
  '1.2.840.10046.2.1': 'Diffie-Hellman',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
};

/** Named elliptic curves → { name, size } (name uses the openssl/sec pairing). */
export const CURVE_OIDS: Record<string, { name: string; size: number }> = {
  '1.2.840.10045.3.1.1': { name: 'prime192v1 / secp192r1', size: 192 },
  '1.2.840.10045.3.1.7': { name: 'prime256v1 / secp256r1', size: 256 },
  '1.3.132.0.1': { name: 'sect163k1', size: 163 },
  '1.3.132.0.10': { name: 'secp256k1', size: 256 },
  '1.3.132.0.33': { name: 'secp224r1', size: 224 },
  '1.3.132.0.34': { name: 'secp384r1', size: 384 },
  '1.3.132.0.35': { name: 'secp521r1', size: 521 },
  '1.3.36.3.3.2.8.1.1.7': { name: 'brainpoolP256r1', size: 256 },
  '1.3.36.3.3.2.8.1.1.11': { name: 'brainpoolP384r1', size: 384 },
  '1.3.36.3.3.2.8.1.1.13': { name: 'brainpoolP512r1', size: 512 },
};

/** Certificate extensions. */
export const EXTENSION_OIDS: Record<string, string> = {
  '2.5.29.9': 'Subject Directory Attributes',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.16': 'Private Key Usage Period',
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.18': 'Issuer Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.20': 'CRL Number',
  '2.5.29.21': 'CRL Reason',
  '2.5.29.24': 'Invalidity Date',
  '2.5.29.27': 'Delta CRL Indicator',
  '2.5.29.28': 'Issuing Distribution Point',
  '2.5.29.29': 'Certificate Issuer',
  '2.5.29.30': 'Name Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.33': 'Policy Mappings',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.36': 'Policy Constraints',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.46': 'Freshest CRL',
  '2.5.29.54': 'Inhibit anyPolicy',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
  '1.3.6.1.5.5.7.1.11': 'Subject Information Access',
  '1.3.6.1.5.5.7.1.24': 'TLS Feature',
  '1.3.6.1.5.5.7.48.1.5': 'OCSP No Check',
  '1.3.6.1.4.1.11129.2.4.2': 'Signed Certificate Timestamp List',
  '1.3.6.1.4.1.11129.2.4.3': 'CT Precertificate Poison',
  '1.2.840.113549.1.9.15': 'S/MIME Capabilities',
  '2.16.840.1.113730.1.1': 'Netscape Certificate Type',
  '2.16.840.1.113730.1.13': 'Netscape Comment',
};

/** Extended key usage purposes. */
export const EKU_OIDS: Record<string, string> = {
  '2.5.29.37.0': 'Any Extended Key Usage',
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'E-mail Protection',
  '1.3.6.1.5.5.7.3.5': 'IPSec End System',
  '1.3.6.1.5.5.7.3.6': 'IPSec Tunnel',
  '1.3.6.1.5.5.7.3.7': 'IPSec User',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.5.5.7.3.17': 'IPSec IKE',
  '1.3.6.1.4.1.311.10.3.4': 'Microsoft Encrypted File System',
  '1.3.6.1.4.1.311.20.2.2': 'Microsoft Smart Card Logon',
  '1.3.6.1.4.1.311.10.3.12': 'Microsoft Document Signing',
};

/** Authority / subject information access methods. */
export const ACCESS_METHOD_OIDS: Record<string, string> = {
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'CA Issuers',
  '1.3.6.1.5.5.7.48.3': 'Time Stamping',
  '1.3.6.1.5.5.7.48.5': 'CA Repository',
};

/** Well-known certificate policies. */
export const POLICY_OIDS: Record<string, string> = {
  '2.23.140.1.1': 'CA/B Forum Extended Validation',
  '2.23.140.1.2.1': 'CA/B Forum Domain Validated',
  '2.23.140.1.2.2': 'CA/B Forum Organization Validated',
  '2.23.140.1.2.3': 'CA/B Forum Individual Validated',
  '2.5.29.32.0': 'Any Policy',
};

/**
 * X.509 KeyUsage bits, in bit-string order (RFC 5280 §4.2.1.3).
 * The order matters — the index is the bit position.
 */
export const KEY_USAGE_BITS: string[] = [
  'Digital Signature',
  'Non Repudiation',
  'Key Encipherment',
  'Data Encipherment',
  'Key Agreement',
  'Certificate Signing',
  'CRL Signing',
  'Encipher Only',
  'Decipher Only',
];

/** Hash algorithms considered unsafe for signatures today. */
export const WEAK_HASHES = new Set(['MD2', 'MD4', 'MD5', 'SHA-1']);

export function oidName(
  oid: string,
  dictionary: Record<string, string>,
): { name: string; known: boolean } {
  const hit = dictionary[oid];
  return hit ? { name: hit, known: true } : { name: oid, known: false };
}
