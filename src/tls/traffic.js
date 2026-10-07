import { hkdfExpandLabel } from './crypto.js';
import { EMPTY_BYTES } from './constants.js';
export const uint64be = (sequenceNumber) => {
    const bytes = new Uint8Array(8);
    return (new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes);
  },
  xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
    const nonce = initializationVector.slice(),
      sequenceBytes = uint64be(sequenceNumber);
    for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
    return nonce;
  },
  deriveTrafficKeys = (hash, secret, keyLen, ivLen) =>
    Promise.all([
      hkdfExpandLabel(hash, secret, 'key', EMPTY_BYTES, keyLen),
      hkdfExpandLabel(hash, secret, 'iv', EMPTY_BYTES, ivLen),
    ]);
