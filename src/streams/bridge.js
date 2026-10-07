import { 创建下行Grain发送器 } from './download.js';
import { 下行Grain包字节 } from '../state.js';
import { log } from '../utils/log.js';
import { closeSocketQuietly } from '../utils/socket.js';
export async function connectStreams(
  remoteSocket,
  webSocket,
  headerData,
  retryFunc,
  isCurrentSocket = null,
  remoteConnWrapper = null,
) {
  let header = headerData,
    hasData = false,
    reader,
    useBYOB = false,
    readError = null;
  const BYOB单次读取上限 = 64 * 1024;
  const 当前连接仍有效 = () => !isCurrentSocket || isCurrentSocket();
  const 下行发送器 = 创建下行Grain发送器(webSocket, header, 当前连接仍有效);
  header = null;
  const 下行控制器 = { 停止并刷新: () => 下行发送器.停止并刷新() };
  if (remoteConnWrapper) remoteConnWrapper.downlinkController = 下行控制器;
  try {
    remoteSocket.closed?.catch?.(() => {});
  } catch (e) {}

  try {
    reader = remoteSocket.readable.getReader({ mode: 'byob' });
    useBYOB = true;
  } catch (e) {
    reader = remoteSocket.readable.getReader();
  }

  try {
    if (!useBYOB) {
      while (true) {
        const { done, value } = await reader.read();
        if (!当前连接仍有效()) break;
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (value.byteLength >= 下行Grain包字节) {
          await 下行发送器.flush();
          await 下行发送器.直接发送(value);
        } else {
          await 下行发送器.发送(value);
        }
      }
    } else {
      let readBuffer = new ArrayBuffer(BYOB单次读取上限);
      while (true) {
        const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
        if (!当前连接仍有效()) break;
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (value.byteLength >= 下行Grain包字节) {
          await 下行发送器.flush();
          await 下行发送器.直接发送(value);
          readBuffer = new ArrayBuffer(BYOB单次读取上限);
        } else {
          await 下行发送器.发送(value.slice());
          readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
        }
      }
    }
    if (当前连接仍有效()) await 下行发送器.flush();
  } catch (err) {
    readError = err;
  } finally {
    if (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {
      try {
        await 下行发送器.停止并刷新();
      } catch (err) {
        readError ||= err;
      }
    }
    if (remoteConnWrapper?.downlinkController === 下行控制器) remoteConnWrapper.downlinkController = null;
    try {
      await reader.cancel();
    } catch (e) {}
    try {
      reader.releaseLock();
    } catch (e) {}
    try {
      remoteSocket.close();
    } catch (e) {}
  }
  if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && 当前连接仍有效()) {
    try {
      await retryFunc();
      return;
    } catch (err) {
      readError ||= err;
    }
  }
  if (!当前连接仍有效()) return;
  if (readError) log(`[TCP下行] 读取失败: ${readError?.message || readError}`);
  closeSocketQuietly(webSocket);
}
