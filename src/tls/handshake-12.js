import {
  HANDSHAKE_TYPE_CERTIFICATE,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
  GROUPS_BY_ID,
  HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
  CONTENT_TYPE_HANDSHAKE,
  CONTENT_TYPE_CHANGE_CIPHER_SPEC,
  HANDSHAKE_TYPE_FINISHED,
  CONTENT_TYPE_ALERT,
  shouldIgnoreTlsAlert,
} from './constants.js';
import { extractLeafCertificate, parseServerKeyExchange, buildHandshakeMessage, buildTlsRecord } from './records.js';
import {
  deriveSharedSecret,
  tlsBytes,
  tls12Prf,
  concatBytes,
  importAesGcmKey,
  digestBytes,
  readUint24,
  constantTimeEqual,
} from './crypto.js';
export async function 完成TLS12握手(reader, writer) {
  /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
  let serverKeyExchange = null;
  let sawServerHelloDone = !1;
  let clientCertRequested = !1;
  if (
    (await this.readHandshakeUntil(
      reader,
      async (message) => {
        switch (message.type) {
          case HANDSHAKE_TYPE_CERTIFICATE: {
            this.recordHandshake(message.raw);
            const certificate = extractLeafCertificate(message.body, 1);
            if (!certificate) throw new Error('Missing TLS 1.2 certificate');
            await this.acceptCertificate(certificate);
            break;
          }
          case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            (this.recordHandshake(message.raw), (serverKeyExchange = parseServerKeyExchange(message.body)));
            break;
          case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
            return (this.recordHandshake(message.raw), (sawServerHelloDone = !0), 1);
          case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            (this.recordHandshake(message.raw), (clientCertRequested = !0));
            break;
          default:
            this.recordHandshake(message.raw);
        }
      },
      'Connection closed during TLS 1.2 handshake',
    ),
    !this.sawCert)
  )
    throw new Error('Missing TLS 1.2 leaf certificate');
  const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (
    serverKeyExchange
  );
  if (!serverKeyExchangeData) throw new Error('Missing TLS 1.2 ServerKeyExchange');
  const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
  if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
  const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
  if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
  const preMasterSecret = await deriveSharedSecret(
      keyShare.keyPair.privateKey,
      serverKeyExchangeData.serverPublicKey,
      curveName,
    ),
    clientKeyExchange = buildHandshakeMessage(
      HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw),
    );
  if (clientCertRequested) {
    const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
    (this.recordHandshake(emptyCertificate),
      await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate)));
  }
  this.recordHandshake(clientKeyExchange);
  const hashName = this.cipherConfig.hash;
  this.masterSecret = await tls12Prf(
    preMasterSecret,
    'master secret',
    concatBytes(this.clientRandom, this.serverRandom),
    48,
    hashName,
  );
  const keyLen = this.cipherConfig.keyLen,
    ivLen = this.cipherConfig.ivLen,
    keyBlock = await tls12Prf(
      this.masterSecret,
      'key expansion',
      concatBytes(this.serverRandom, this.clientRandom),
      2 * keyLen + 2 * ivLen,
      hashName,
    );
  ((this.clientWriteKey = keyBlock.slice(0, keyLen)),
    (this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen)),
    (this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen)),
    (this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen)));
  if (!this.cipherConfig.chacha)
    [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([
      importAesGcmKey(this.clientWriteKey, ['encrypt']),
      importAesGcmKey(this.serverWriteKey, ['decrypt']),
    ]);
  (await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)),
    await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1))));
  const clientVerifyData = await tls12Prf(
      this.masterSecret,
      'client finished',
      await digestBytes(hashName, this.transcript()),
      12,
      hashName,
    ),
    finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
  (this.recordHandshake(finishedMessage),
    await writer.write(
      buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)),
    ));
  let sawChangeCipherSpec = !1;
  await this.readRecordsUntil(
    reader,
    async (record) => {
      if (record.type === CONTENT_TYPE_ALERT) {
        if (shouldIgnoreTlsAlert(record.fragment)) return;
        throw new Error(`TLS Alert: ${record.fragment[1]}`);
      }
      if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
      if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
      const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
      if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
      const verifyLength = readUint24(decrypted, 1),
        verifyData = decrypted.slice(4, 4 + verifyLength),
        expectedVerifyData = await tls12Prf(
          this.masterSecret,
          'server finished',
          await digestBytes(hashName, this.transcript()),
          12,
          hashName,
        );
      if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error('TLS 1.2 server Finished verify failed');
      return 1;
    },
    'Connection closed waiting for TLS 1.2 Finished',
  );
}
