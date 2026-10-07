import { textEncoder } from './constants.js';
export const tlsBytes = (...parts) => {
  const flattenBytes = (values) =>
    values.flatMap((value) =>
      value instanceof Uint8Array
        ? [...value]
        : Array.isArray(value)
          ? flattenBytes(value)
          : 'number' == typeof value
            ? [value]
            : [],
    );
  return new Uint8Array(flattenBytes(parts));
};

export const uint16be = (value) => [(value >> 8) & 255, 255 & value];

export const readUint16 = (buffer, offset) => (buffer[offset] << 8) | buffer[offset + 1];

export const readUint24 = (buffer, offset) => (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];

export const concatBytes = (...chunks) => {
  const nonEmptyChunks = chunks.filter((chunk) => chunk && chunk.length > 0),
    length = nonEmptyChunks.reduce((total, chunk) => total + chunk.length, 0),
    result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of nonEmptyChunks) (result.set(chunk, offset), (offset += chunk.length));
  return result;
};

export const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));

export const constantTimeEqual = (left, right) => {
  if (!left || !right || left.length !== right.length) return !1;
  let diff = 0;
  for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
  return 0 === diff;
};

export const hashByteLength = (hash) => ('SHA-512' === hash ? 64 : 'SHA-384' === hash ? 48 : 32);

export async function hmac(hash, key, data) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, !1, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, data));
}

export async function digestBytes(hash, data) {
  return new Uint8Array(await crypto.subtle.digest(hash, data));
}

export async function tls12Prf(secret, label, seed, length, hash = 'SHA-256') {
  const labelSeed = concatBytes(textEncoder.encode(label), seed);
  let output = new Uint8Array(0),
    currentA = labelSeed;
  for (; output.length < length;) {
    currentA = await hmac(hash, secret, currentA);
    const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
    output = concatBytes(output, block);
  }
  return output.slice(0, length);
}

export async function hkdfExtract(hash, salt, inputKeyMaterial) {
  return ((salt && salt.length) || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial));
}

export async function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = textEncoder.encode('tls13 ' + label);
  return (async function (hash, secret, info, length) {
    const hashLen = hashByteLength(hash),
      roundCount = Math.ceil(length / hashLen);
    let output = new Uint8Array(0),
      previousBlock = new Uint8Array(0);
    for (let round = 1; round <= roundCount; round++)
      ((previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round]))),
        (output = concatBytes(output, previousBlock)));
    return output.slice(0, length);
  })(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length);
}

export async function generateKeyShare(group = 'P-256') {
  const algorithm = 'X25519' === group ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group };
  const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ['deriveBits']));
  const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey('raw', keyPair.publicKey));
  return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) };
}

export async function deriveSharedSecret(privateKey, peerPublicKey, group = 'P-256') {
  const algorithm = 'X25519' === group ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group },
    peerKey = await crypto.subtle.importKey('raw', peerPublicKey, algorithm, !1, []),
    bits = 'P-384' === group ? 384 : 'P-521' === group ? 528 : 256;
  return new Uint8Array(
    await crypto.subtle.deriveBits(/** @type {any} */ ({ name: algorithm.name, public: peerKey }), privateKey, bits),
  );
}

export async function importAesGcmKey(key, usages) {
  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, !1, usages);
}

export async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: initializationVector, additionalData, tagLength: 128 },
      cryptoKey,
      plaintext,
    ),
  );
}

export async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: initializationVector, additionalData, tagLength: 128 },
      cryptoKey,
      ciphertext,
    ),
  );
}
