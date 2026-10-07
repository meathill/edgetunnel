import {
  randomBytes,
  concatBytes,
  generateKeyShare,
  uint16be,
  importAesGcmKey,
  aesGcmEncryptWithKey,
  aesGcmDecryptWithKey,
  tlsBytes,
} from './crypto.js';
import {
  TlsRecordParser,
  TlsHandshakeParser,
  buildClientHello,
  buildTlsRecord,
  parseServerHello,
  TLS_MAX_PLAINTEXT_FRAGMENT,
} from './records.js';
import {
  CIPHER_SUITES_BY_ID,
  CONTENT_TYPE_ALERT,
  shouldIgnoreTlsAlert,
  CONTENT_TYPE_HANDSHAKE,
  TLS_VERSION_10,
  HANDSHAKE_TYPE_SERVER_HELLO,
  TLS_VERSION_12,
  CONTENT_TYPE_APPLICATION_DATA,
  EMPTY_BYTES,
  ALERT_CLOSE_NOTIFY,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET,
  HANDSHAKE_TYPE_KEY_UPDATE,
} from './constants.js';
import { withTimeout } from '../turn-protocol.js';
import { 完成TLS12握手 } from './handshake-12.js';
import { 完成TLS13握手 } from './handshake-13.js';
import { uint64be, xorSequenceIntoIv } from './traffic.js';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from './chacha.js';
import { 数据转Uint8Array } from '../utils/bytes.js';
export class TlsClient {
  constructor(socket, options = {}) {
    if (
      ((this.socket = socket),
      (this.serverName = options.serverName || ''),
      (this.supportTls13 = !1 !== options.tls13),
      (this.supportTls12 = !1 !== options.tls12),
      !this.supportTls13 && !this.supportTls12)
    )
      throw new Error('At least one TLS version must be enabled');
    ((this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null),
      (this.allowChacha = options.allowChacha !== false),
      (this.timeout = options.timeout ?? 3e4),
      (this.clientRandom = randomBytes(32)),
      (this.serverRandom = null),
      (this.handshakeChunks = []),
      (this.handshakeComplete = !1),
      (this.negotiatedAlpn = null),
      (this.cipherSuite = null),
      (this.cipherConfig = null),
      (this.isTls13 = !1),
      (this.masterSecret = null),
      (this.handshakeSecret = null),
      (this.clientWriteKey = null),
      (this.serverWriteKey = null),
      (this.clientWriteIv = null),
      (this.serverWriteIv = null),
      (this.clientHandshakeKey = null),
      (this.serverHandshakeKey = null),
      (this.clientHandshakeIv = null),
      (this.serverHandshakeIv = null),
      (this.clientAppKey = null),
      (this.serverAppKey = null),
      (this.clientAppIv = null),
      (this.serverAppIv = null),
      (this.clientWriteCryptoKey = null),
      (this.serverWriteCryptoKey = null),
      (this.clientHandshakeCryptoKey = null),
      (this.serverHandshakeCryptoKey = null),
      (this.clientAppCryptoKey = null),
      (this.serverAppCryptoKey = null),
      (this.clientSeqNum = 0n),
      (this.serverSeqNum = 0n),
      (this.recordParser = new TlsRecordParser()),
      (this.handshakeParser = new TlsHandshakeParser()),
      (this.keyPairs = new Map()),
      (this.ecdhKeyPair = null),
      (this.sawCert = !1));
  }
  recordHandshake(chunk) {
    this.handshakeChunks.push(chunk);
  }
  transcript() {
    return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks);
  }
  getCipherConfig(cipherSuite) {
    return CIPHER_SUITES_BY_ID.get(cipherSuite) || null;
  }
  async readChunk(reader) {
    return this.timeout ? withTimeout(reader.read(), this.timeout, 'TLS read timeout') : reader.read();
  }
  async readRecordsUntil(reader, predicate, closedError) {
    for (;;) {
      let record;
      for (; (record = this.recordParser.next());) if (await predicate(record)) return;
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error(closedError);
      this.recordParser.feed(value);
    }
  }
  async readHandshakeUntil(reader, predicate, closedError) {
    for (let message; (message = this.handshakeParser.next());) if (await predicate(message)) return;
    return this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type === CONTENT_TYPE_HANDSHAKE) {
          this.handshakeParser.feed(record.fragment);
          for (let message; (message = this.handshakeParser.next());) if (await predicate(message)) return 1;
        }
      },
      closedError,
    );
  }
  async acceptCertificate(certificate) {
    if (!certificate?.length) throw new Error('Empty certificate');
    this.sawCert = !0;
  }
  async handshake() {
    const [p256Share, x25519Share] = await Promise.all([generateKeyShare('P-256'), generateKeyShare('X25519')]);
    ((this.keyPairs = new Map([
      [23, p256Share],
      [29, x25519Share],
    ])),
      (this.ecdhKeyPair = p256Share.keyPair));
    const reader = this.socket.readable.getReader(),
      writer = this.socket.writable.getWriter();
    try {
      const clientHello = buildClientHello(
        this.clientRandom,
        this.serverName,
        { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw },
        { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha },
      );
      (this.recordHandshake(clientHello),
        await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10)));
      const serverHello = await this.receiveServerHello(reader);
      if (serverHello.isHRR) throw new Error('HelloRetryRequest is not supported by TLSClientMini');
      if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
        const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
        this.ecdhKeyPair = selectedKeyPair.keyPair;
      }
      (serverHello.isTls13
        ? await this.handshakeTls13(reader, writer, serverHello)
        : await this.handshakeTls12(reader, writer),
        (this.handshakeComplete = !0));
    } finally {
      (reader.releaseLock(), writer.releaseLock());
    }
  }
  async receiveServerHello(reader) {
    for (;;) {
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error('Connection closed waiting for ServerHello');
      let record;
      for (this.recordParser.feed(value); (record = this.recordParser.next());) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) continue;
          throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
        let message;
        for (this.handshakeParser.feed(record.fragment); (message = this.handshakeParser.next());) {
          if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
          this.recordHandshake(message.raw);
          const serverHello = parseServerHello(message.body);
          if (
            ((this.serverRandom = serverHello.serverRandom),
            (this.cipherSuite = serverHello.cipherSuite),
            (this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite)),
            (this.isTls13 = serverHello.isTls13),
            (this.negotiatedAlpn = serverHello.alpn || null),
            !this.cipherConfig)
          )
            throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
          return serverHello;
        }
      }
    }
  }
  async handshakeTls12(reader, writer) {
    return 完成TLS12握手.call(this, reader, writer);
  }
  async handshakeTls13(reader, writer, serverHello) {
    return 完成TLS13握手.call(this, reader, writer, serverHello);
  }
  async encryptTls12(plaintext, contentType) {
    const sequenceNumber = this.clientSeqNum++,
      sequenceBytes = uint64be(sequenceNumber),
      additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
      return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData);
    }
    const explicitNonce = randomBytes(8);
    if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ['encrypt']);
    return concatBytes(
      explicitNonce,
      await aesGcmEncryptWithKey(
        this.clientWriteCryptoKey,
        concatBytes(this.clientWriteIv, explicitNonce),
        plaintext,
        additionalData,
      ),
    );
  }
  async decryptTls12(ciphertext, contentType) {
    const sequenceNumber = this.serverSeqNum++,
      sequenceBytes = uint64be(sequenceNumber);
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
      return chacha20Poly1305Decrypt(
        this.serverWriteKey,
        nonce,
        ciphertext,
        concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)),
      );
    }
    const explicitNonce = ciphertext.subarray(0, 8),
      encryptedData = ciphertext.subarray(8);
    if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ['decrypt']);
    return aesGcmDecryptWithKey(
      this.serverWriteCryptoKey,
      concatBytes(this.serverWriteIv, explicitNonce),
      encryptedData,
      concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)),
    );
  }
  async encryptTls13Handshake(plaintext) {
    const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
      additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
    if (this.cipherConfig.chacha)
      return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
    if (!this.clientHandshakeCryptoKey)
      this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ['encrypt']);
    return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData);
  }
  async decryptTls13Handshake(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
      additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
    const decrypted = this.cipherConfig.chacha
      ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData)
      : await aesGcmDecryptWithKey(
          this.serverHandshakeCryptoKey ||
            (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ['decrypt'])),
          nonce,
          ciphertext,
          additionalData,
        );
    let innerTypeIndex = decrypted.length - 1;
    for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
    return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1);
  }
  async encryptTls13(data) {
    const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
      nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
      additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
    if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
    if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ['encrypt']);
    return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData);
  }
  async decryptTls13(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
      additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
      plaintext = this.cipherConfig.chacha
        ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData)
        : await aesGcmDecryptWithKey(
            this.serverAppCryptoKey ||
              (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ['decrypt'])),
            nonce,
            ciphertext,
            additionalData,
          );
    let innerTypeIndex = plaintext.length - 1;
    for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
    if (innerTypeIndex < 0)
      return {
        data: EMPTY_BYTES,
        type: 0,
      };
    return {
      data: plaintext.slice(0, innerTypeIndex),
      type: plaintext[innerTypeIndex],
    };
  }
  async write(data) {
    if (!this.handshakeComplete) throw new Error('Handshake not complete');
    const plaintext = 数据转Uint8Array(data);
    if (!plaintext.byteLength) return;
    const writer = this.socket.writable.getWriter();
    try {
      const records = [];
      for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
        const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
        const encrypted = this.isTls13
          ? await this.encryptTls13(chunk)
          : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
        records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
      }
      await writer.write(records.length === 1 ? records[0] : concatBytes(...records));
    } finally {
      writer.releaseLock();
    }
  }
  async read() {
    for (;;) {
      let record;
      for (; (record = this.recordParser.next());) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
        if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
        const { data, type } = await this.decryptTls13(record.fragment);
        if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
        if (type === CONTENT_TYPE_ALERT) {
          if (data[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${data[1]}`);
        }
        if (type !== CONTENT_TYPE_HANDSHAKE) continue;
        let message;
        for (this.handshakeParser.feed(data); (message = this.handshakeParser.next());)
          if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE)
            throw new Error('TLS 1.3 KeyUpdate is not supported by TLSClientMini');
      }
      const reader = this.socket.readable.getReader();
      try {
        const { value, done } = await this.readChunk(reader);
        if (done) return null;
        this.recordParser.feed(value);
      } finally {
        reader.releaseLock();
      }
    }
  }
  close() {
    this.socket.close();
  }
}
