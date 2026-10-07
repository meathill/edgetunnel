import {
  TLS_VERSION_12,
  EXT_SUPPORTED_VERSIONS,
  EXT_KEY_SHARE,
  EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
  textDecoder,
  TLS_VERSION_13,
  textEncoder,
  EXT_SERVER_NAME,
  EXT_EC_POINT_FORMATS,
  EXT_SUPPORTED_GROUPS,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  EXT_SIGNATURE_ALGORITHMS,
  EXT_PSK_KEY_EXCHANGE_MODES,
  HANDSHAKE_TYPE_CLIENT_HELLO,
} from './constants.js';
import { 数据转Uint8Array } from '../utils/bytes.js';
import { tlsBytes, concatBytes, readUint16, readUint24, constantTimeEqual, uint16be } from './crypto.js';
export const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;

export function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
  const data = 数据转Uint8Array(fragment);
  const record = new Uint8Array(5 + data.byteLength);
  record[0] = contentType;
  record[1] = (version >> 8) & 255;
  record[2] = version & 255;
  record[3] = (data.byteLength >> 8) & 255;
  record[4] = data.byteLength & 255;
  record.set(data, 5);
  return record;
}

export function buildHandshakeMessage(handshakeType, body) {
  return tlsBytes(
    handshakeType,
    ((length) => [(length >> 16) & 255, (length >> 8) & 255, 255 & length])(body.length),
    body,
  );
}

export class TlsRecordParser {
  constructor() {
    this.buffer = new Uint8Array(0);
  }
  feed(chunk) {
    const bytes = 数据转Uint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 5) return null;
    const contentType = this.buffer[0],
      version = readUint16(this.buffer, 1),
      length = readUint16(this.buffer, 3);
    if (this.buffer.length < 5 + length) return null;
    const fragment = this.buffer.subarray(5, 5 + length);
    return ((this.buffer = this.buffer.subarray(5 + length)), { type: contentType, version, length, fragment });
  }
}

export class TlsHandshakeParser {
  constructor() {
    this.buffer = new Uint8Array(0);
  }
  feed(chunk) {
    const bytes = 数据转Uint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 4) return null;
    const handshakeType = this.buffer[0],
      length = readUint24(this.buffer, 1);
    if (this.buffer.length < 4 + length) return null;
    const body = this.buffer.subarray(4, 4 + length),
      raw = this.buffer.subarray(0, 4 + length);
    return ((this.buffer = this.buffer.subarray(4 + length)), { type: handshakeType, length, body, raw });
  }
}

export function parseServerHello(body) {
  let offset = 0;
  const legacyVersion = readUint16(body, offset);
  offset += 2;
  const serverRandom = body.slice(offset, offset + 32);
  offset += 32;
  const sessionIdLength = body[offset++],
    sessionId = body.slice(offset, offset + sessionIdLength);
  offset += sessionIdLength;
  const cipherSuite = readUint16(body, offset);
  offset += 2;
  const compression = body[offset++];
  let selectedVersion = legacyVersion,
    keyShare = null,
    alpn = null;
  if (offset < body.length) {
    const extensionsLength = readUint16(body, offset);
    offset += 2;
    const extensionsEnd = offset + extensionsLength;
    for (; offset + 4 <= extensionsEnd;) {
      const extensionType = readUint16(body, offset);
      offset += 2;
      const extensionLength = readUint16(body, offset);
      offset += 2;
      const extensionData = body.slice(offset, offset + extensionLength);
      if (((offset += extensionLength), extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2))
        selectedVersion = readUint16(extensionData, 0);
      else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
        const group = readUint16(extensionData, 0),
          keyLength = readUint16(extensionData, 2);
        keyShare = { group, key: extensionData.slice(4, 4 + keyLength) };
      } else
        extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION &&
          extensionLength >= 3 &&
          (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])));
    }
  }
  const helloRetryRequestRandom = new Uint8Array([
    207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7,
    158, 9, 226, 200, 168, 51, 156,
  ]);
  return {
    version: legacyVersion,
    serverRandom,
    sessionId,
    cipherSuite,
    compression,
    selectedVersion,
    keyShare,
    alpn,
    isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom),
    isTls13: selectedVersion === TLS_VERSION_13,
  };
}

export function parseServerKeyExchange(body) {
  let offset = 1;
  const namedCurve = readUint16(body, offset);
  offset += 2;
  const keyLength = body[offset++];
  return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) };
}

export function extractLeafCertificate(body, hasContext = 0) {
  let offset = 0;
  if (hasContext) {
    const contextLength = body[offset++];
    offset += contextLength;
  }
  if (offset + 3 > body.length) return null;
  const certificateListLength = readUint24(body, offset);
  if (((offset += 3), !certificateListLength || offset + 3 > body.length)) return null;
  const certificateLength = readUint24(body, offset);
  return ((offset += 3), certificateLength ? body.slice(offset, offset + certificateLength) : null);
}

export function parseEncryptedExtensions(body) {
  const parsed = { alpn: null };
  let offset = 2;
  const extensionsEnd = 2 + readUint16(body, 0);
  for (; offset + 4 <= extensionsEnd;) {
    const extensionType = readUint16(body, offset);
    offset += 2;
    const extensionLength = readUint16(body, offset);
    if (((offset += 2), extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3)) {
      const protocolLength = body[offset + 2];
      protocolLength > 0 &&
        offset + 3 + protocolLength <= offset + extensionLength &&
        (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)));
    }
    offset += extensionLength;
  }
  return parsed;
}

export function buildClientHello(
  clientRandom,
  serverName,
  keyShares,
  { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {},
) {
  const cipherIds = [];
  (enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])),
    enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : [])));
  const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
    extensions = [tlsBytes(255, 1, 0, 1, 0)];
  if (serverName) {
    const serverNameBytes = textEncoder.encode(serverName),
      serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
    extensions.push(
      tlsBytes(
        uint16be(EXT_SERVER_NAME),
        uint16be(serverNameList.length + 2),
        uint16be(serverNameList.length),
        serverNameList,
      ),
    );
  }
  (extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)),
    extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23)));
  const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
  extensions.push(
    tlsBytes(
      uint16be(EXT_SIGNATURE_ALGORITHMS),
      uint16be(signatureBytes.length + 2),
      uint16be(signatureBytes.length),
      signatureBytes,
    ),
  );
  const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
  if (protocols.length) {
    const alpnBytes = concatBytes(
      ...protocols.map((protocol) => {
        const protocolBytes = textEncoder.encode(protocol);
        return tlsBytes(protocolBytes.length, protocolBytes);
      }),
    );
    extensions.push(
      tlsBytes(
        uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        uint16be(alpnBytes.length + 2),
        uint16be(alpnBytes.length),
        alpnBytes,
      ),
    );
  }
  if (enableTls13 && keyShares) {
    let keyShareBytes;
    if (
      (extensions.push(
        enableTls12
          ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3)
          : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4),
      ),
      extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)),
      keyShares?.x25519 && keyShares?.p256)
    )
      keyShareBytes = concatBytes(
        tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519),
        tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256),
      );
    else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
    else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
    else {
      if (!(keyShares instanceof Uint8Array)) throw new Error('Invalid keyShares');
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
    }
    extensions.push(
      tlsBytes(
        uint16be(EXT_KEY_SHARE),
        uint16be(keyShareBytes.length + 2),
        uint16be(keyShareBytes.length),
        keyShareBytes,
      ),
    );
  }
  const extensionsBytes = concatBytes(...extensions);
  return buildHandshakeMessage(
    HANDSHAKE_TYPE_CLIENT_HELLO,
    tlsBytes(
      uint16be(TLS_VERSION_12),
      clientRandom,
      0,
      uint16be(cipherBytes.length),
      cipherBytes,
      1,
      0,
      uint16be(extensionsBytes.length),
      extensionsBytes,
    ),
  );
}
