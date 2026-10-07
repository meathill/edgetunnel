import {
  GROUPS_BY_ID,
  EMPTY_BYTES,
  HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
  HANDSHAKE_TYPE_CERTIFICATE,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
  HANDSHAKE_TYPE_FINISHED,
  CONTENT_TYPE_CHANGE_CIPHER_SPEC,
  CONTENT_TYPE_HANDSHAKE,
  CONTENT_TYPE_ALERT,
  shouldIgnoreTlsAlert,
  CONTENT_TYPE_APPLICATION_DATA,
} from './constants.js';
import {
  hashByteLength,
  deriveSharedSecret,
  hkdfExtract,
  hkdfExpandLabel,
  digestBytes,
  importAesGcmKey,
  hmac,
  constantTimeEqual,
  tlsBytes,
  concatBytes,
} from './crypto.js';
import { deriveTrafficKeys } from './traffic.js';
import { parseEncryptedExtensions, extractLeafCertificate, buildHandshakeMessage, buildTlsRecord } from './records.js';
export async function 完成TLS13握手(reader, writer, serverHello) {
  const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
  if (!groupName || !serverHello.keyShare?.key?.length) throw new Error('Missing TLS 1.3 key_share');
  const hashName = this.cipherConfig.hash,
    hashLen = hashByteLength(hashName),
    keyLen = this.cipherConfig.keyLen,
    ivLen = this.cipherConfig.ivLen,
    sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
    earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
    derivedSecret = await hkdfExpandLabel(
      hashName,
      earlySecret,
      'derived',
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen,
    );
  this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
  const transcriptHash = await digestBytes(hashName, this.transcript()),
    clientHandshakeTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      'c hs traffic',
      transcriptHash,
      hashLen,
    ),
    serverHandshakeTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      's hs traffic',
      transcriptHash,
      hashLen,
    );
  (([this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(
    hashName,
    clientHandshakeTrafficSecret,
    keyLen,
    ivLen,
  )),
    ([this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(
      hashName,
      serverHandshakeTrafficSecret,
      keyLen,
      ivLen,
    )));
  if (!this.cipherConfig.chacha)
    [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([
      importAesGcmKey(this.clientHandshakeKey, ['encrypt']),
      importAesGcmKey(this.serverHandshakeKey, ['decrypt']),
    ]);
  const serverFinishedKey = await hkdfExpandLabel(
    hashName,
    serverHandshakeTrafficSecret,
    'finished',
    EMPTY_BYTES,
    hashLen,
  );
  let serverFinishedReceived = !1;
  let clientCertRequested = !1;
  const handleHandshakeMessage = async (message) => {
    switch (message.type) {
      case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
        const encryptedExtensions = parseEncryptedExtensions(message.body);
        (encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn),
          this.recordHandshake(message.raw));
        break;
      }
      case HANDSHAKE_TYPE_CERTIFICATE: {
        const certificate = extractLeafCertificate(message.body);
        if (!certificate) throw new Error('Missing TLS 1.3 certificate');
        (await this.acceptCertificate(certificate), this.recordHandshake(message.raw));
        break;
      }
      case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
        (this.recordHandshake(message.raw), (clientCertRequested = !0));
        break;
      case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
        this.recordHandshake(message.raw);
        break;
      case HANDSHAKE_TYPE_FINISHED: {
        const expectedVerifyData = await hmac(
          hashName,
          serverFinishedKey,
          await digestBytes(hashName, this.transcript()),
        );
        if (!constantTimeEqual(expectedVerifyData, message.body))
          throw new Error('TLS 1.3 server Finished verify failed');
        (this.recordHandshake(message.raw), (serverFinishedReceived = !0));
        break;
      }
      default:
        this.recordHandshake(message.raw);
    }
  };
  await this.readRecordsUntil(
    reader,
    async (record) => {
      if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
      if (record.type === CONTENT_TYPE_ALERT) {
        if (shouldIgnoreTlsAlert(record.fragment)) return;
        throw new Error(`TLS Alert: ${record.fragment[1]}`);
      }
      if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
      const decrypted = await this.decryptTls13Handshake(record.fragment),
        innerType = decrypted[decrypted.length - 1],
        plaintext = decrypted.slice(0, -1);
      if (innerType === CONTENT_TYPE_HANDSHAKE) {
        this.handshakeParser.feed(plaintext);
        for (let message; (message = this.handshakeParser.next());)
          if ((await handleHandshakeMessage(message), serverFinishedReceived)) return 1;
      }
    },
    'Connection closed during TLS 1.3 handshake',
  );
  const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
    masterDerivedSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      'derived',
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen,
    ),
    masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
    clientAppTrafficSecret = await hkdfExpandLabel(
      hashName,
      masterSecret,
      'c ap traffic',
      applicationTranscriptHash,
      hashLen,
    ),
    serverAppTrafficSecret = await hkdfExpandLabel(
      hashName,
      masterSecret,
      's ap traffic',
      applicationTranscriptHash,
      hashLen,
    );
  (([this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen)),
    ([this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen)));
  if (!this.cipherConfig.chacha)
    [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([
      importAesGcmKey(this.clientAppKey, ['encrypt']),
      importAesGcmKey(this.serverAppKey, ['decrypt']),
    ]);
  let clientFlightHandshake = EMPTY_BYTES;
  if (clientCertRequested)
    ((clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0))),
      this.recordHandshake(clientFlightHandshake));
  const clientFinishedKey = await hkdfExpandLabel(
      hashName,
      clientHandshakeTrafficSecret,
      'finished',
      EMPTY_BYTES,
      hashLen,
    ),
    clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
    clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
  (this.recordHandshake(clientFinishedMessage),
    await writer.write(
      buildTlsRecord(
        CONTENT_TYPE_APPLICATION_DATA,
        await this.encryptTls13Handshake(
          concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE]),
        ),
      ),
    ),
    (this.clientSeqNum = 0n),
    (this.serverSeqNum = 0n));
}
