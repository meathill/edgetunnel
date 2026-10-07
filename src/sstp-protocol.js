import { 数据转Uint8Array } from './utils/bytes.js';
export const SSTP_TCP_MSS = 1400;

export const SSTP_EMPTY_BYTES = new Uint8Array(0);

export function readSstpUint16(bytes, offset = 0) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

export function readSstpUint32(bytes, offset = 0) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

export function randomSstpUint16() {
  return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

export function internetChecksum(bytes, offset, length) {
  let sum = 0;
  for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
  if (length & 1) sum += bytes[offset + length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

export const buildSstpDataPacket = (pppFrame) => {
  const packetLength = 6 + pppFrame.byteLength;
  const packet = new Uint8Array(packetLength);
  packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
  packet.set(pppFrame, 6);
  return packet;
};

export const buildPppConfigurePacket = (protocol, code, id, options = []) => {
  const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
  const frame = new Uint8Array(6 + optionsLength);
  const view = new DataView(frame.buffer);
  view.setUint16(0, protocol);
  frame[2] = code;
  frame[3] = id;
  view.setUint16(4, 4 + optionsLength);
  options.reduce((offset, option) => {
    frame[offset] = option.type;
    frame[offset + 1] = 2 + option.data.byteLength;
    frame.set(option.data, offset + 2);
    return offset + 2 + option.data.byteLength;
  }, 6);
  return frame;
};

export const parsePPPFrame = (data) => {
  const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
  if (data.byteLength - offset < 4) return null;
  const protocol = readSstpUint16(data, offset);
  if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
  if (data.byteLength - offset < 6) return null;
  return {
    protocol,
    code: data[offset + 2],
    id: data[offset + 3],
    payload: data.subarray(offset + 6),
    rawPacket: data.subarray(offset),
  };
};

export const parsePppOptions = (data) => {
  const options = [];
  for (let offset = 0; offset + 2 <= data.byteLength;) {
    const type = data[offset];
    const length = data[offset + 1];
    if (length < 2 || offset + length > data.byteLength) break;
    options.push({ type, data: data.subarray(offset + 2, offset + length) });
    offset += length;
  }
  return options;
};

export function 匹配SSTPTCP包(ipPacket, targetPort, sourcePort) {
  if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
  const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
  if (ipPacket.byteLength < ipHeaderLength + 20) return null;
  if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
  if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
  return {
    flags: ipPacket[ipHeaderLength + 13],
    sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
    payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4,
  };
}

export function 构造SSTPTCP帧(
  flags,
  payload = SSTP_EMPTY_BYTES,
  { ipHeaderTemplate, tcpPseudoHeader, sourcePort, targetPort, sequenceNumber, acknowledgementNumber },
) {
  const bytes = 数据转Uint8Array(payload);
  const payloadLength = bytes.byteLength;
  const tcpLength = 20 + payloadLength;
  const ipLength = 20 + tcpLength;
  const sstpLength = 8 + ipLength;
  const frame = new Uint8Array(sstpLength);
  const view = new DataView(frame.buffer);
  frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
  frame.set(ipHeaderTemplate, 8);
  view.setUint16(10, ipLength);
  view.setUint16(12, randomSstpUint16());
  view.setUint16(18, internetChecksum(frame, 8, 20));
  view.setUint16(28, sourcePort);
  view.setUint16(30, targetPort);
  view.setUint32(32, sequenceNumber);
  view.setUint32(36, acknowledgementNumber);
  frame[40] = 0x50;
  frame[41] = flags;
  view.setUint16(42, 65535);
  if (payloadLength) frame.set(bytes, 48);
  tcpPseudoHeader[10] = tcpLength >> 8;
  tcpPseudoHeader[11] = tcpLength & 0xff;
  tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
  view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
  return frame;
}
