import { concatBytes } from './crypto.js';
export function rotateLeft32(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

export function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
  ((state[indexA] = (state[indexA] + state[indexB]) >>> 0),
    (state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16)),
    (state[indexC] = (state[indexC] + state[indexD]) >>> 0),
    (state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12)),
    (state[indexA] = (state[indexA] + state[indexB]) >>> 0),
    (state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8)),
    (state[indexC] = (state[indexC] + state[indexD]) >>> 0),
    (state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)));
}

export function chacha20Block(key, counter, nonce) {
  const state = new Uint32Array(16);
  ((state[0] = 1634760805), (state[1] = 857760878), (state[2] = 2036477234), (state[3] = 1797285236));
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
  state[12] = counter;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  ((state[13] = nonceView.getUint32(0, !0)),
    (state[14] = nonceView.getUint32(4, !0)),
    (state[15] = nonceView.getUint32(8, !0)));
  const workingState = new Uint32Array(state);
  for (let round = 0; round < 10; round++)
    (chachaQuarterRound(workingState, 0, 4, 8, 12),
      chachaQuarterRound(workingState, 1, 5, 9, 13),
      chachaQuarterRound(workingState, 2, 6, 10, 14),
      chachaQuarterRound(workingState, 3, 7, 11, 15),
      chachaQuarterRound(workingState, 0, 5, 10, 15),
      chachaQuarterRound(workingState, 1, 6, 11, 12),
      chachaQuarterRound(workingState, 2, 7, 8, 13),
      chachaQuarterRound(workingState, 3, 4, 9, 14));
  for (let wordIndex = 0; wordIndex < 16; wordIndex++)
    workingState[wordIndex] = (workingState[wordIndex] + state[wordIndex]) >>> 0;
  return new Uint8Array(workingState.buffer.slice(0));
}

export function chacha20Xor(key, nonce, data) {
  const output = new Uint8Array(data.length);
  let counter = 1;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, counter++, nonce),
      blockLength = Math.min(64, data.length - offset);
    for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index];
  }
  return output;
}

export function poly1305Mac(key, message) {
  const rKey = (function (rBytes) {
      const clamped = new Uint8Array(rBytes);
      return (
        (clamped[3] &= 15),
        (clamped[7] &= 15),
        (clamped[11] &= 15),
        (clamped[15] &= 15),
        (clamped[4] &= 252),
        (clamped[8] &= 252),
        (clamped[12] &= 252),
        clamped
      );
    })(key.slice(0, 16)),
    sKey = key.slice(16, 32);
  let accumulator = [0n, 0n, 0n, 0n, 0n];
  const rLimbs = [
    0x3ffffffn & BigInt(rKey[0] | (rKey[1] << 8) | (rKey[2] << 16) | (rKey[3] << 24)),
    0x3ffffffn & BigInt((rKey[3] >> 2) | (rKey[4] << 6) | (rKey[5] << 14) | (rKey[6] << 22)),
    0x3ffffffn & BigInt((rKey[6] >> 4) | (rKey[7] << 4) | (rKey[8] << 12) | (rKey[9] << 20)),
    0x3ffffffn & BigInt((rKey[9] >> 6) | (rKey[10] << 2) | (rKey[11] << 10) | (rKey[12] << 18)),
    0x3ffffffn & BigInt(rKey[13] | (rKey[14] << 8) | (rKey[15] << 16)),
  ];
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.slice(offset, offset + 16),
      paddedChunk = new Uint8Array(17);
    (paddedChunk.set(chunk),
      (paddedChunk[chunk.length] = 1),
      (accumulator[0] += BigInt(
        paddedChunk[0] | (paddedChunk[1] << 8) | (paddedChunk[2] << 16) | ((3 & paddedChunk[3]) << 24),
      )),
      (accumulator[1] += BigInt(
        (paddedChunk[3] >> 2) | (paddedChunk[4] << 6) | (paddedChunk[5] << 14) | ((15 & paddedChunk[6]) << 22),
      )),
      (accumulator[2] += BigInt(
        (paddedChunk[6] >> 4) | (paddedChunk[7] << 4) | (paddedChunk[8] << 12) | ((63 & paddedChunk[9]) << 20),
      )),
      (accumulator[3] += BigInt(
        (paddedChunk[9] >> 6) | (paddedChunk[10] << 2) | (paddedChunk[11] << 10) | (paddedChunk[12] << 18),
      )),
      (accumulator[4] += BigInt(
        paddedChunk[13] | (paddedChunk[14] << 8) | (paddedChunk[15] << 16) | (paddedChunk[16] << 24),
      )));
    const product = [0n, 0n, 0n, 0n, 0n];
    for (let accIndex = 0; accIndex < 5; accIndex++)
      for (let rIndex = 0; rIndex < 5; rIndex++) {
        const limbIndex = accIndex + rIndex;
        limbIndex < 5
          ? (product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex])
          : (product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n);
      }
    let carry = 0n;
    for (let index = 0; index < 5; index++)
      ((product[index] += carry), (accumulator[index] = 0x3ffffffn & product[index]), (carry = product[index] >> 26n));
    ((accumulator[0] += 5n * carry),
      (carry = accumulator[0] >> 26n),
      (accumulator[0] &= 0x3ffffffn),
      (accumulator[1] += carry));
  }
  let tagValue =
    accumulator[0] |
    (accumulator[1] << 26n) |
    (accumulator[2] << 52n) |
    (accumulator[3] << 78n) |
    (accumulator[4] << 104n);
  tagValue =
    (tagValue + sKey.reduce((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index)), 0n)) &
    ((1n << 128n) - 1n);
  const tag = new Uint8Array(16);
  for (let index = 0; index < 16; index++) tag[index] = Number((tagValue >> BigInt(8 * index)) & 0xffn);
  return tag;
}

export function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
    ciphertext = chacha20Xor(key, nonce, plaintext),
    aadPadding = (16 - (additionalData.length % 16)) % 16,
    ciphertextPadding = (16 - (ciphertext.length % 16)) % 16,
    macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
  (macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding));
  const lengthView = new DataView(
    macData.buffer,
    additionalData.length + aadPadding + ciphertext.length + ciphertextPadding,
  );
  (lengthView.setBigUint64(0, BigInt(additionalData.length), !0),
    lengthView.setBigUint64(8, BigInt(ciphertext.length), !0));
  const tag = poly1305Mac(polyKey, macData);
  return concatBytes(ciphertext, tag);
}

export function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
  if (ciphertext.length < 16) throw new Error('Ciphertext too short');
  const tag = ciphertext.slice(-16),
    encryptedData = ciphertext.slice(0, -16),
    polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
    aadPadding = (16 - (additionalData.length % 16)) % 16,
    ciphertextPadding = (16 - (encryptedData.length % 16)) % 16,
    macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
  (macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding));
  const lengthView = new DataView(
    macData.buffer,
    additionalData.length + aadPadding + encryptedData.length + ciphertextPadding,
  );
  (lengthView.setBigUint64(0, BigInt(additionalData.length), !0),
    lengthView.setBigUint64(8, BigInt(encryptedData.length), !0));
  const expectedTag = poly1305Mac(polyKey, macData);
  let diff = 0;
  for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
  if (0 !== diff) throw new Error('ChaCha20-Poly1305 authentication failed');
  return chacha20Xor(key, nonce, encryptedData);
}
