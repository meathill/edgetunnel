import { stripIPv6Brackets } from './utils/address.js';
import {
  isIPv4,
  withTimeout,
  CONNECT_TIMEOUT_MS,
  TURN_STUN_MAGIC_COOKIE,
  createTurnStunAttribute,
  TURN_STUN_ATTR,
  writeTurnBytes,
  createTurnStunMessage,
  TURN_STUN_TYPE,
  randomTurnTransactionId,
  readTurnStunMessage,
  addTurnMessageIntegrity,
  parseTurnErrorCode,
} from './turn-protocol.js';
import { DoH查询 } from './dns.js';
import { textDecoder, textEncoder } from './tls/constants.js';
import { 拼接字节数据 } from './utils/bytes.js';
export async function turnConnect(proxy, targetHost, targetPort, TCP连接) {
  proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
  const resolvedTargetHost = stripIPv6Brackets(targetHost);
  /** @type {string | null} */
  let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
  if (!targetIp) {
    const records = await DoH查询(resolvedTargetHost, 'A');
    const recordData = records.find((item) => item.type === 1 && isIPv4(item.data))?.data;
    targetIp = typeof recordData === 'string' ? recordData : null;
  }
  if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

  const turnHost = stripIPv6Brackets(proxy.hostname);
  let controlSocket = null,
    dataSocket = null,
    controlWriter = null,
    controlReader = null,
    dataWriter = null,
    dataReader = null,
    dataReaderReleased = false;
  const close = () => {
    try {
      controlSocket?.close?.();
    } catch (e) {}
    try {
      dataSocket?.close?.();
    } catch (e) {}
  };
  const releaseDataReader = () => {
    if (dataReaderReleased) return;
    dataReaderReleased = true;
    try {
      dataReader?.releaseLock?.();
    } catch (e) {}
  };

  try {
    controlSocket = TCP连接({ hostname: turnHost, port: proxy.port });
    await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
    controlWriter = controlSocket.writable.getWriter();
    controlReader = controlSocket.readable.getReader();

    const xorPeerAddress = new Uint8Array(8);
    xorPeerAddress[1] = 1;
    new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
    targetIp.split('.').forEach((value, index) => {
      xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
    });
    const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
    const requestedTransport = new Uint8Array([6, 0, 0, 0]);

    await writeTurnBytes(
      controlWriter,
      createTurnStunMessage(TURN_STUN_TYPE.ALLOCATE_REQUEST, randomTurnTransactionId(), [
        createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
      ]),
      'TURN Allocate request timed out',
    );

    let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
    let message = turnResponse.message;
    let bufferedData = turnResponse.extraData;
    let integrityKey = null;
    let authAttributes = [];
    const sign = (messageToSign) =>
      integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

    if (
      message.type === TURN_STUN_TYPE.ALLOCATE_ERROR &&
      proxy.username !== null &&
      proxy.password !== null &&
      parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
    ) {
      const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
      const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
      if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

      const realm = textDecoder.decode(realmBytes);
      integrityKey = new Uint8Array(
        await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)),
      );
      authAttributes = [
        createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
        createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
        createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce),
      ];

      const allocateRequest = await addTurnMessageIntegrity(
        createTurnStunMessage(TURN_STUN_TYPE.ALLOCATE_REQUEST, randomTurnTransactionId(), [
          createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
          ...authAttributes,
        ]),
        integrityKey,
      );
      const pipelinedMessages = await Promise.all([
        sign(
          createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [
            peerAddress,
            ...authAttributes,
          ]),
        ),
        sign(
          createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [
            peerAddress,
            ...authAttributes,
          ]),
        ),
      ]);
      await writeTurnBytes(
        controlWriter,
        拼接字节数据(allocateRequest, ...pipelinedMessages),
        'TURN authenticated Allocate request timed out',
      );
      turnResponse = await readTurnStunMessage(
        controlReader,
        bufferedData,
        'TURN authenticated Allocate response timed out',
      );
      message = turnResponse.message;
      bufferedData = turnResponse.extraData;
    } else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
      const pipelinedMessages = await Promise.all([
        sign(
          createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [
            peerAddress,
            ...authAttributes,
          ]),
        ),
        sign(
          createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [
            peerAddress,
            ...authAttributes,
          ]),
        ),
      ]);
      if (pipelinedMessages.length)
        await writeTurnBytes(controlWriter, 拼接字节数据(...pipelinedMessages), 'TURN pipelined request timed out');
    }

    if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
      const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
      throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
    }

    dataSocket = TCP连接({ hostname: turnHost, port: proxy.port });
    turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
    message = turnResponse.message;
    bufferedData = turnResponse.extraData;
    if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

    turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
    message = turnResponse.message;
    bufferedData = turnResponse.extraData;
    if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID])
      throw new Error('TURN CONNECT failed');

    await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
    dataWriter = dataSocket.writable.getWriter();
    dataReader = dataSocket.readable.getReader();
    await writeTurnBytes(
      dataWriter,
      await sign(
        createTurnStunMessage(TURN_STUN_TYPE.CONNECTION_BIND_REQUEST, randomTurnTransactionId(), [
          createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
          ...authAttributes,
        ]),
      ),
      'TURN ConnectionBind request timed out',
    );

    turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
    message = turnResponse.message;
    const extraPayload = turnResponse.extraData;
    if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

    controlWriter.releaseLock();
    controlWriter = null;
    controlReader.releaseLock();
    controlReader = null;
    dataWriter.releaseLock();
    dataWriter = null;

    const readable = new ReadableStream({
      start(controller) {
        if (extraPayload?.byteLength) controller.enqueue(extraPayload);
      },
      pull(controller) {
        return dataReader.read().then(({ done, value }) => {
          if (done) {
            releaseDataReader();
            controller.close();
          } else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
        });
      },
      cancel() {
        try {
          dataReader?.cancel?.();
        } catch (e) {}
        releaseDataReader();
        close();
      },
    });

    return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
  } catch (error) {
    try {
      controlWriter?.releaseLock?.();
    } catch (e) {}
    try {
      controlReader?.releaseLock?.();
    } catch (e) {}
    try {
      dataWriter?.releaseLock?.();
    } catch (e) {}
    releaseDataReader();
    close();
    throw error;
  }
}
