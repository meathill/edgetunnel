import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { 创建上行写入队列 } from '../streams/upload-queue.js';
import { 创建上行Grain合包流 } from '../streams/upload-stream.js';
import { 创建下行Grain发送器 } from '../streams/download.js';
import { connectStreams } from '../streams/bridge.js';
import { 开始TCP连接世代, 失效TCP连接世代 } from '../connection.js';
import { socket, webSocket } from './fixtures/helpers.js';

beforeEach(() => {
  vi.stubGlobal('WebSocket', { OPEN: 1, CLOSING: 2 });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

describe('上传背压、错误与重连', () => {
  it('写入并等待必须等待远端写完成，保持顺序', async () => {
    const gate = deferred(),
      writes = [];
    const writer = {
      write: vi.fn(async (data) => {
        writes.push([...data]);
        if (writes.length === 1) await gate.promise;
      }),
    };
    const queue = 创建上行写入队列({ 获取写入器: () => writer });
    let completed = false;
    const first = queue.写入并等待(new Uint8Array([1, 2])).then(() => {
      completed = true;
    });
    const second = queue.写入并等待(new Uint8Array([3, 4]));
    await vi.waitFor(() => expect(writer.write).toHaveBeenCalledTimes(1));
    expect(completed).toBe(false);
    gate.resolve();
    await Promise.all([first, second, queue.等待空()]);
    expect(writes.flat()).toEqual([1, 2, 3, 4]);
    queue.清空();
  });

  it('清空队列释放活动和等待写入，不留下悬挂 Promise', async () => {
    const gate = deferred();
    const writer = { write: vi.fn(() => gate.promise) };
    const queue = 创建上行写入队列({ 获取写入器: () => writer });
    const first = queue.写入并等待(new Uint8Array([1])).catch((error) => error);
    const second = queue.写入并等待(new Uint8Array([2])).catch((error) => error);
    await vi.waitFor(() => expect(writer.write).toHaveBeenCalled());
    queue.清空();
    expect((await first).message).toContain('queue closed');
    expect((await second).message).toContain('queue closed');
    gate.resolve();
    await queue.等待空();
    expect(queue.写入(new Uint8Array([3]))).toBe(false);
  });

  it('重拨期间等待新 writer，按原顺序发送一次', async () => {
    const gate = deferred();
    const writer = { write: vi.fn(async () => {}) };
    let connected = false;
    const queue = 创建上行写入队列({ 获取写入器: () => (connected ? writer : null), 获取连接任务: () => gate.promise });
    const pending = queue.写入并等待(new Uint8Array([5, 6]));
    expect(writer.write).not.toHaveBeenCalled();
    connected = true;
    gate.resolve();
    expect(await pending).toBe(true);
    expect([...writer.write.mock.calls[0][0]]).toEqual([5, 6]);
    queue.清空();
  });

  it('写入失败切换 writer 并重试当前块', async () => {
    let writer = {
      write: vi.fn(async () => {
        throw new Error('old connection');
      }),
    };
    const next = { write: vi.fn(async () => {}) };
    const retry = vi.fn(async () => {
      writer = next;
    });
    const queue = 创建上行写入队列({ 获取写入器: () => writer, 重试连接: retry });
    await queue.写入并等待(new Uint8Array([7]));
    expect(retry).toHaveBeenCalledTimes(1);
    expect([...next.write.mock.calls[0][0]]).toEqual([7]);
    queue.清空();
  });

  it('上传队列字节超限关闭连接', () => {
    const close = vi.fn();
    const queue = 创建上行写入队列({ 获取写入器: () => ({ write: async () => {} }), 关闭连接: close });
    expect(() => queue.写入(new Uint8Array(16 * 1024 * 1024 + 1))).toThrow('upload queue overflow');
    expect(close).toHaveBeenCalledTimes(1);
  });

  it('上传队列条目超限关闭连接并释放等待项', async () => {
    const gate = deferred(),
      close = vi.fn();
    const queue = 创建上行写入队列({ 获取写入器: () => null, 获取连接任务: () => gate.promise, 关闭连接: close });
    const pending = queue.写入并等待(new Uint8Array([1])).catch((error) => error);
    for (let i = 0; i < 4096; i++) queue.写入(new Uint8Array([2]));
    expect(() => queue.写入(new Uint8Array([3]))).toThrow('upload queue overflow');
    expect((await pending).isQueueOverflow).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    gate.resolve();
    await queue.等待空();
  });

  it('合包流跨过容量边界和尾包时保持完整字节顺序', async () => {
    const stream = 创建上行Grain合包流(4);
    const received = [];
    const reading = stream.readable.pipeTo(
      new WritableStream({
        write(data) {
          received.push(...data);
        },
      }),
    );
    await stream.写入(new Uint8Array([1, 2]));
    await stream.写入(new Uint8Array([3, 4, 5]));
    await stream.写入(new Uint8Array([6, 7, 8, 9, 10]));
    await stream.写入(new Uint8Array([11]));
    await stream.结束();
    await reading;
    expect(received).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  });
});

describe('下行合包和连接世代', () => {
  it('小包、大包和 flush 串行发送，协议头只发送一次', async () => {
    const ws = webSocket();
    const sender = 创建下行Grain发送器(ws, new Uint8Array([99]));
    await sender.发送(new Uint8Array([1, 2]));
    await sender.发送(new Uint8Array(32768).fill(3));
    await sender.直接发送(new Uint8Array([4]));
    await sender.停止并刷新();
    const bytes = ws.send.mock.calls.flatMap(([data]) => [
      ...new Uint8Array(data.buffer || data, data.byteOffset || 0, data.byteLength),
    ]);
    expect(bytes).toEqual([99, 1, 2, ...new Array(32768).fill(3), 4]);
  });

  it('重连先排空旧下行，旧 socket 收尾不会关闭新连接', async () => {
    const drain = deferred(),
      old = socket(),
      newer = socket();
    const wrapper = { socket: old, generation: 0, downlinkController: { 停止并刷新: () => drain.promise } };
    const { generation, downlinkDrain } = 开始TCP连接世代(wrapper);
    expect(old.close).toHaveBeenCalledTimes(1);
    expect(generation).toBe(1);
    let ready = false;
    const installing = downlinkDrain.then(() => {
      ready = true;
      wrapper.socket = newer;
    });
    expect(ready).toBe(false);
    drain.resolve();
    await installing;
    const ws = webSocket();
    await connectStreams(socket([new Uint8Array([1])]), ws, null, null, () => false, wrapper);
    expect(wrapper.socket).toBe(newer);
    expect(ws.close).not.toHaveBeenCalled();
    expect(ws.send).not.toHaveBeenCalled();
    失效TCP连接世代(wrapper);
    expect(newer.close).toHaveBeenCalledTimes(1);
    expect(wrapper.socket).toBeNull();
  });

  it('空下行触发反代重试，响应头保留给真实数据', async () => {
    const ws = webSocket(),
      header = vi.fn(() => new Uint8Array([99]));
    const retry = vi.fn(async () => {});
    await connectStreams(socket(), ws, header, retry);
    expect(retry).toHaveBeenCalledTimes(1);
    expect(header).not.toHaveBeenCalled();
    expect(ws.close).not.toHaveBeenCalled();
  });
});
