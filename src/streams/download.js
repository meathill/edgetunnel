import { 下行Grain包字节, 下行Grain尾部阈值, 下行Grain最大等待轮次, 下行Grain低水位字节 } from '../state.js';
import { 创建Grain收纳器 } from './grain-buffer.js';
import { closeSocketQuietly, WebSocket发送并等待 } from '../utils/socket.js';
import { 数据转Uint8Array } from '../utils/bytes.js';
export function 创建下行Grain发送器(webSocket, headerData = null, isActive = null) {
  const packetCap = 下行Grain包字节;
  const tailBytes = 下行Grain尾部阈值;
  const grain = 创建Grain收纳器(packetCap, true);
  let header = typeof headerData === 'function' ? null : headerData;
  const 获取响应头 =
    typeof headerData === 'function'
      ? headerData
      : () => {
          const value = header;
          header = null;
          return value;
        };
  let flushTimer = null;
  let generation = 0;
  let scheduledGeneration = 0;
  let waitRounds = 0;
  let flushPromise = null;
  let directSendPromise = null;
  let 强制排空 = false;
  let 停止已开始 = false;
  let 活动发送数 = 0;
  let 活动直发数 = 0;
  let 活动发送错误 = null;
  let 活动发送等待者 = [];
  const 等待活动发送完成 = () => {
    if (!活动发送数 && !活动直发数) return Promise.resolve();
    return new Promise((resolve) => 活动发送等待者.push(resolve));
  };
  const 标记发送完成 = () => {
    if (活动发送数 || 活动直发数 || !活动发送等待者.length) return;
    const resolvers = 活动发送等待者;
    活动发送等待者 = [];
    for (const resolve of resolvers) resolve();
  };
  const 检查活动发送错误 = () => {
    if (!活动发送错误) return;
    const err = 活动发送错误;
    grain.清空();
    throw err;
  };
  const 当前发送器有效 = () => 强制排空 || !isActive || isActive();
  const 关闭活动连接 = () => {
    if (当前发送器有效()) closeSocketQuietly(webSocket);
  };

  const 发送原始块 = async (chunk) => {
    if (!当前发送器有效()) return;
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
    chunk = 附加响应头(chunk);
    await WebSocket发送并等待(webSocket, chunk);
  };

  const 串行发送原始块 = async (chunk) => {
    while (directSendPromise) await directSendPromise;
    const sendTask = 发送原始块(chunk);
    directSendPromise = sendTask;
    try {
      await sendTask;
    } finally {
      if (directSendPromise === sendTask) directSendPromise = null;
    }
  };

  const 附加响应头 = (chunk) => {
    const responseHeader = 获取响应头();
    if (!responseHeader) return chunk;
    const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
    merged.set(responseHeader, 0);
    merged.set(chunk, responseHeader.length);
    return merged;
  };

  const flush = async () => {
    while (flushPromise) await flushPromise;
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null;
    waitRounds = 0;
    if (!当前发送器有效()) {
      grain.清空();
      return;
    }
    const 发送任务 = (async () => {
      for (;;) {
        if (!当前发送器有效()) {
          grain.清空();
          break;
        }
        const packed = grain.合包();
        if (!packed) break;
        await 串行发送原始块(packed.chunk);
      }
    })();
    flushPromise = 发送任务
      .catch((err) => {
        活动发送错误 ||= err;
        throw err;
      })
      .finally(() => {
        flushPromise = null;
      });
    return flushPromise;
  };

  const scheduleFlush = () => {
    if (!当前发送器有效()) {
      grain.清空();
      return;
    }
    if (grain.为空 || flushTimer) return;
    if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
      flush().catch(关闭活动连接);
      return;
    }
    flushTimer = setTimeout(() => {
      flushTimer = null;
      if (!当前发送器有效()) {
        grain.清空();
        return;
      }
      if (grain.为空) return;
      if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
        flush().catch(关闭活动连接);
        return;
      }
      if (
        waitRounds < 下行Grain最大等待轮次 &&
        (generation !== scheduledGeneration || grain.字节数 < 下行Grain低水位字节)
      ) {
        waitRounds++;
        scheduledGeneration = generation;
        scheduleFlush();
        return;
      }
      flush().catch(关闭活动连接);
    }, 1);
  };

  return {
    async 直接发送(data) {
      if (停止已开始 || !当前发送器有效()) return;
      活动直发数++;
      try {
        await flush();
        const chunk = 数据转Uint8Array(data);
        if (!chunk.byteLength) return;
        await 串行发送原始块(chunk);
      } catch (err) {
        活动发送错误 ||= err;
        throw err;
      } finally {
        活动直发数--;
        标记发送完成();
      }
    },
    async 发送(data) {
      if (停止已开始 || !当前发送器有效()) return;
      活动发送数++;
      try {
        const chunk = 数据转Uint8Array(data);
        if (!chunk.byteLength) return;
        let offset = 0;
        const totalBytes = chunk.byteLength;
        while (offset < totalBytes) {
          const remainingBytes = totalBytes - offset;
          if (grain.为空 && remainingBytes >= packetCap) {
            const sendBytes = Math.min(packetCap, remainingBytes);
            const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
            await 串行发送原始块(view);
            offset += sendBytes;
            continue;
          }
          const copyBytes = Math.min(packetCap - grain.字节数, totalBytes - offset);
          if (!copyBytes) {
            await flush();
            continue;
          }
          grain.收纳({
            chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk,
          });
          offset += copyBytes;
          generation++;
          if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) await flush();
          else scheduleFlush();
        }
      } catch (err) {
        活动发送错误 ||= err;
        throw err;
      } finally {
        活动发送数--;
        标记发送完成();
      }
    },
    flush,
    async 停止并刷新() {
      if (停止已开始) {
        await 等待活动发送完成();
        while (directSendPromise) await directSendPromise;
        检查活动发送错误();
        await flush();
        return;
      }
      停止已开始 = true;
      强制排空 = true;
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = null;
      await 等待活动发送完成();
      while (directSendPromise) await directSendPromise;
      检查活动发送错误();
      await flush();
    },
  };
}
