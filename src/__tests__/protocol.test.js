import { describe, it, expect } from 'vitest';
import { formatIdentifier, 解析木马请求, 解析魏烈思请求 } from '../protocol.js';
import { sha224 } from '../utils/crypto.js';

describe('formatIdentifier', () => {
  it('should format 16 bytes as a UUID-like string', () => {
    const bytes = new Uint8Array([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    expect(formatIdentifier(bytes)).toBe('01234567-89ab-cdef-0123-456789abcdef');
  });

  it('should support offset', () => {
    const bytes = new Uint8Array(20);
    bytes.set([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00], 4);
    expect(formatIdentifier(bytes, 4)).toBe('ffeeddcc-bbaa-9988-7766-554433221100');
  });
});

describe('解析木马请求', () => {
  function buildTrojanBuffer(password, hostname, port) {
    const hash = sha224(password);
    const encoder = new TextEncoder();
    const hashBytes = encoder.encode(hash);
    const hostBytes = encoder.encode(hostname);

    // hash(56) + CRLF(2) + cmd(1) + atype(1) + addrLen(1) + host + port(2) + CRLF(2) + payload
    const buf = new Uint8Array(56 + 2 + 1 + 1 + 1 + hostBytes.length + 2 + 2);
    buf.set(hashBytes, 0);
    buf[56] = 0x0d; // CR
    buf[57] = 0x0a; // LF
    buf[58] = 0x01; // TCP
    buf[59] = 0x03; // Domain
    buf[60] = hostBytes.length;
    buf.set(hostBytes, 61);
    const portOffset = 61 + hostBytes.length;
    buf[portOffset] = (port >> 8) & 0xff;
    buf[portOffset + 1] = port & 0xff;
    buf[portOffset + 2] = 0x0d;
    buf[portOffset + 3] = 0x0a;
    return buf.buffer;
  }

  it('should parse a valid Trojan request', () => {
    const buffer = buildTrojanBuffer('test-uuid', 'example.com', 443);
    const result = 解析木马请求(buffer, 'test-uuid');
    expect(result.hasError).toBe(false);
    expect(result.hostname).toBe('example.com');
    expect(result.port).toBe(443);
    expect(result.addressType).toBe(3);
  });

  it('should reject invalid password', () => {
    const buffer = buildTrojanBuffer('correct', 'example.com', 443);
    const result = 解析木马请求(buffer, 'wrong');
    expect(result.hasError).toBe(true);
    expect(result.message).toContain('invalid password');
  });

  it('should reject too-short buffer', () => {
    const result = 解析木马请求(new ArrayBuffer(10), 'test');
    expect(result.hasError).toBe(true);
  });
});

describe('解析魏烈思请求', () => {
  function buildVlessBuffer(uuid, hostname, port, cmd = 1) {
    // Parse UUID hex to 16 bytes
    const hexStr = uuid.replace(/-/g, '');
    const uuidBytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      uuidBytes[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
    }

    const hostBytes = new TextEncoder().encode(hostname);
    // version(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + addrType(1) + addrLen(1) + host + padding
    const totalLen = 1 + 16 + 1 + 1 + 2 + 1 + 1 + hostBytes.length + 4;
    const buf = new Uint8Array(totalLen);
    buf[0] = 0; // version
    buf.set(uuidBytes, 1);
    buf[17] = 0; // optLen
    buf[18] = cmd; // command (1=TCP, 2=UDP)
    // port (big-endian)
    buf[19] = (port >> 8) & 0xff;
    buf[20] = port & 0xff;
    buf[21] = 2; // address type: domain
    buf[22] = hostBytes.length;
    buf.set(hostBytes, 23);
    return buf.buffer;
  }

  const testUUID = '01234567-89ab-4def-8123-456789abcdef';

  it('should parse a valid VLESS TCP request', () => {
    const buffer = buildVlessBuffer(testUUID, 'example.com', 443);
    const result = 解析魏烈思请求(buffer, testUUID);
    expect(result.hasError).toBe(false);
    expect(result.hostname).toBe('example.com');
    expect(result.port).toBe(443);
    expect(result.isUDP).toBe(false);
  });

  it('should detect UDP command', () => {
    const buffer = buildVlessBuffer(testUUID, 'example.com', 53, 2);
    const result = 解析魏烈思请求(buffer, testUUID);
    expect(result.hasError).toBe(false);
    expect(result.isUDP).toBe(true);
  });

  it('should reject mismatched UUID', () => {
    const buffer = buildVlessBuffer(testUUID, 'example.com', 443);
    const result = 解析魏烈思请求(buffer, '00000000-0000-4000-8000-000000000000');
    expect(result.hasError).toBe(true);
    expect(result.message).toContain('uuid');
  });

  it('should reject too-short data', () => {
    const result = 解析魏烈思请求(new ArrayBuffer(5), testUUID);
    expect(result.hasError).toBe(true);
  });
});
