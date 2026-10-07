import { 构造SSTPTCP帧 } from './sstp-protocol.js';
import { 创建SSTP读取器 } from './sstp-reader.js';
import { stripIPv6Brackets } from './utils/address.js';
import { withTimeout, CONNECT_TIMEOUT_MS, isIPv4 } from './turn-protocol.js';
import { textEncoder } from './tls/constants.js';
import { 拼接字节数据, 数据转Uint8Array } from './utils/bytes.js';
import {
  buildSstpDataPacket,
  buildPppConfigurePacket,
  parsePPPFrame,
  parsePppOptions,
  readSstpUint16,
  匹配SSTPTCP包,
  randomSstpUint16,
  readSstpUint32,
  SSTP_TCP_MSS,
} from './sstp-protocol.js';
import { DoH查询 } from './dns.js';
export async function sstpConnect(proxy, targetHost, targetPort, TCP连接) {
  proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
  let pppIdentifier = 1,
    socket = null,
    reader = null,
    writer = null;
  let closedSettled = false,
    resolveClosed,
    rejectClosed;
  const closed = new Promise((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });
  const settleClosed = (settle, value) => {
    if (closedSettled) return;
    closedSettled = true;
    settle(value);
  };
  const close = () => {
    try {
      reader?.cancel?.().catch?.(() => {});
    } catch (e) {}
    try {
      reader?.releaseLock?.();
    } catch (e) {}
    try {
      writer?.close?.().catch?.(() => {});
    } catch (e) {}
    try {
      writer?.releaseLock?.();
    } catch (e) {}
    try {
      socket?.close?.();
    } catch (e) {}
    settleClosed(resolveClosed);
  };

  const 读取器 = 创建SSTP读取器(() => reader);
  const { readHttpLine, readPacket } = 读取器;
  try {
    const serverHost = stripIPv6Brackets(proxy.hostname);
    const serverPort = proxy.port;
    socket = TCP连接({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
    await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();

    const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
    const httpRequest = textEncoder.encode(
      `SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n` +
        `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n` +
        'Content-Length: 18446744073709551615\r\n' +
        `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`,
    );
    const encapsulatedProtocol = new Uint8Array(2);
    new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
    const maximumReceiveUnit = new Uint8Array(2);
    new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
    const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
    const sstpConnectView = new DataView(sstpConnectRequest.buffer);
    sstpConnectRequest[0] = 0x10;
    sstpConnectRequest[1] = 0x01;
    sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
    sstpConnectView.setUint16(4, 0x0001);
    sstpConnectView.setUint16(6, 1);
    sstpConnectRequest[9] = 1;
    sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
    sstpConnectRequest.set(encapsulatedProtocol, 12);

    await withTimeout(
      writer.write(
        拼接字节数据(
          httpRequest,
          sstpConnectRequest,
          buildSstpDataPacket(
            buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [{ type: 1, data: maximumReceiveUnit }]),
          ),
        ),
      ),
      CONNECT_TIMEOUT_MS,
      'SSTP HTTP handshake request timed out',
    );

    const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
    for (;;) {
      const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
      if (line === '') break;
    }
    if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine))
      throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

    let localLcpAcked = false,
      peerLcpAcked = false,
      papRequired = false,
      papSent = false,
      papDone = false,
      ipcpStarted = false,
      ipcpFinished = false,
      sourceIp = null;
    const sendPapIfReady = async () => {
      if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
      if (proxy.username === null || proxy.password === null)
        throw new Error('SSTP server requires PAP authentication');
      const username = textEncoder.encode(proxy.username);
      const password = textEncoder.encode(proxy.password);
      if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
      const papLength = 6 + username.byteLength + password.byteLength;
      const frame = new Uint8Array(2 + papLength);
      const view = new DataView(frame.buffer);
      view.setUint16(0, 0xc023);
      frame[2] = 1;
      frame[3] = pppIdentifier++;
      view.setUint16(4, papLength);
      frame[6] = username.byteLength;
      frame.set(username, 7);
      frame[7 + username.byteLength] = password.byteLength;
      frame.set(password, 8 + username.byteLength);
      await withTimeout(
        writer.write(buildSstpDataPacket(frame)),
        CONNECT_TIMEOUT_MS,
        'SSTP PAP authentication request timed out',
      );
      papSent = true;
    };
    const startIpcpIfReady = async () => {
      if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
      await withTimeout(
        writer.write(
          buildSstpDataPacket(
            buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [{ type: 3, data: new Uint8Array(4) }]),
          ),
        ),
        CONNECT_TIMEOUT_MS,
        'SSTP IPCP request timed out',
      );
      ipcpStarted = true;
    };

    for (let round = 0; round < 50 && !ipcpFinished; round++) {
      const packet = await readPacket(CONNECT_TIMEOUT_MS);
      if (packet.isControl) continue;
      const ppp = parsePPPFrame(packet.body);
      if (!ppp) continue;

      if (ppp.protocol === 0xc021) {
        if (ppp.code === 1) {
          const authOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
          if (authOption?.data?.byteLength >= 2) {
            const authProtocol = readSstpUint16(authOption.data);
            if (authProtocol !== 0xc023)
              throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
            papRequired = true;
          }
          const ack = new Uint8Array(ppp.rawPacket);
          ack[2] = 2;
          await withTimeout(
            writer.write(buildSstpDataPacket(ack)),
            CONNECT_TIMEOUT_MS,
            'SSTP LCP Configure-Ack timed out',
          );
          peerLcpAcked = true;
          await sendPapIfReady();
          await startIpcpIfReady();
        } else if (ppp.code === 2) {
          localLcpAcked = true;
          await sendPapIfReady();
          await startIpcpIfReady();
        }
        continue;
      }

      if (ppp.protocol === 0xc023) {
        if (ppp.code === 2) {
          papDone = true;
          await startIpcpIfReady();
        } else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
        continue;
      }

      if (ppp.protocol === 0x8021) {
        if (ppp.code === 1) {
          const ack = new Uint8Array(ppp.rawPacket);
          ack[2] = 2;
          await withTimeout(
            writer.write(buildSstpDataPacket(ack)),
            CONNECT_TIMEOUT_MS,
            'SSTP IPCP Configure-Ack timed out',
          );
          await startIpcpIfReady();
        } else if (ppp.code === 3) {
          const addressOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
          if (addressOption?.data?.byteLength === 4) {
            sourceIp = [...addressOption.data].join('.');
            await withTimeout(
              writer.write(
                buildSstpDataPacket(
                  buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [{ type: 3, data: addressOption.data }]),
                ),
              ),
              CONNECT_TIMEOUT_MS,
              'SSTP IPCP address request timed out',
            );
            ipcpStarted = true;
          }
        } else if (ppp.code === 2) {
          const addressOption = parsePppOptions(ppp.payload).find((option) => option.type === 3);
          if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
          ipcpFinished = true;
        }
      }
    }
    if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

    const target = stripIPv6Brackets(targetHost);
    /** @type {string | null} */
    let targetIp = isIPv4(target) ? target : null;
    if (!targetIp) {
      const records = await DoH查询(target, 'A');
      const recordData = records.find((item) => item.type === 1 && isIPv4(item.data))?.data;
      targetIp = typeof recordData === 'string' ? recordData : null;
    }
    if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

    const matchIncomingIpPacket = (ipPacket) => 匹配SSTPTCP包(ipPacket, targetPort, sourcePort);
    const sourcePort = 10000 + (randomSstpUint16() % 50000);
    const sourceAddress = new Uint8Array(
      String(sourceIp || '')
        .split('.')
        .map(Number),
    );
    const destinationAddress = new Uint8Array(
      String(targetIp || '')
        .split('.')
        .map(Number),
    );
    let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
    let acknowledgementNumber = 0;
    const ipHeaderTemplate = new Uint8Array(20);
    ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
    ipHeaderTemplate.set(sourceAddress, 12);
    ipHeaderTemplate.set(destinationAddress, 16);
    const tcpPseudoHeader = new Uint8Array(1432);
    tcpPseudoHeader.set(sourceAddress);
    tcpPseudoHeader.set(destinationAddress, 4);
    tcpPseudoHeader[9] = 6;
    const buildTcpFrame = (flags, payload) =>
      构造SSTPTCP帧(flags, payload, {
        ipHeaderTemplate,
        tcpPseudoHeader,
        sourcePort,
        targetPort,
        sequenceNumber,
        acknowledgementNumber,
      });

    await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
    sequenceNumber = (sequenceNumber + 1) >>> 0;
    let tcpReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      const packet = await readPacket(CONNECT_TIMEOUT_MS);
      if (packet.isControl) continue;
      const ppp = parsePPPFrame(packet.body);
      if (!ppp || ppp.protocol !== 0x0021) continue;
      const tcp = matchIncomingIpPacket(ppp.ipPacket);
      if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
      acknowledgementNumber = (tcp.sequence + 1) >>> 0;
      await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
      tcpReady = true;
      break;
    }
    if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

    /** @type {ReadableStreamDefaultController<Uint8Array> | null} */
    let streamController = null;
    const readable = new ReadableStream({
      start(controller) {
        streamController = controller;
      },
      cancel() {
        close();
      },
    });

    (async () => {
      try {
        let pendingChunks = [],
          pendingLength = 0;
        const flush = () => {
          if (!pendingLength) return;
          if (!streamController) throw new Error('SSTP readable stream is not ready');
          streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : 拼接字节数据(...pendingChunks));
          pendingChunks = [];
          pendingLength = 0;
          writer.write(buildTcpFrame(0x10)).catch(() => {});
        };

        for (;;) {
          const packet = await readPacket(60000);
          if (packet.isControl) continue;
          const ppp = parsePPPFrame(packet.body);
          if (!ppp || ppp.protocol !== 0x0021) continue;
          const incoming = matchIncomingIpPacket(ppp.ipPacket);
          if (!incoming) continue;

          if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
            const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
            if (payload.byteLength) {
              acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
              pendingChunks.push(new Uint8Array(payload));
              pendingLength += payload.byteLength;
            }
          }

          if (incoming.flags & 0x01) {
            flush();
            acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
            writer.write(buildTcpFrame(0x11)).catch(() => {});
            const controller = streamController;
            if (controller) {
              try {
                controller.close();
              } catch (e) {}
            }
            close();
            return;
          }

          if (读取器.剩余字节数 < 4 || pendingLength >= 32768) flush();
        }
      } catch (error) {
        const controller = streamController;
        if (controller) {
          try {
            controller.error(error);
          } catch (e) {}
        }
        settleClosed(rejectClosed, error);
        try {
          socket?.close?.();
        } catch (e) {}
      }
    })();

    const writable = new WritableStream({
      async write(chunk) {
        const bytes = 数据转Uint8Array(chunk);
        if (!bytes.byteLength) return;
        if (bytes.byteLength <= SSTP_TCP_MSS) {
          await writer.write(buildTcpFrame(0x18, bytes));
          sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
          return;
        }
        const frames = [];
        for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
          const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
          frames.push(buildTcpFrame(0x18, segment));
          sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
        }
        await writer.write(拼接字节数据(...frames));
      },
      close() {
        return writer.write(buildTcpFrame(0x11)).catch(() => {});
      },
      abort(error) {
        close();
        if (error) settleClosed(rejectClosed, error);
      },
    });

    return { readable, writable, closed, close };
  } catch (error) {
    close();
    throw error;
  }
}
