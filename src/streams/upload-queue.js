import { 创建Grain收纳器 } from './grain-buffer.js';
import { 上行合包目标字节, 上行队列最大字节, 上行队列最大条目 } from '../state.js';
import { log } from '../utils/log.js';
import { 数据转Uint8Array } from '../utils/bytes.js';
export function 创建上行写入队列({
  获取写入器,
  获取连接任务 = null,
  释放写入器,
  重试连接,
  关闭连接,
  名称 = '上行队列',
}) {
  const grain = 创建Grain收纳器(上行合包目标字节);
  let draining = false;
  let closed = false;
  let idleResolvers = [];
  let activeCompletions = null;

  const settleCompletions = (completions, err = null) => {
    if (!completions) return;
    for (const completion of completions) {
      if (err) completion.reject(err);
      else completion.resolve();
    }
  };

  const resolveIdle = () => {
    if (grain.字节数 || draining || !idleResolvers.length) return;
    const resolvers = idleResolvers;
    idleResolvers = [];
    for (const resolve of resolvers) resolve();
  };

  const clear = (err = null) => {
    const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
    if (closeErr) {
      grain.清空((item) => settleCompletions(item.completions, closeErr));
      settleCompletions(activeCompletions, closeErr);
      activeCompletions = null;
    } else grain.清空();
    resolveIdle();
  };

  const bundle = () => {
    const packed = grain.合包();
    if (!packed) return null;
    let allowRetry = true;
    let completions = null;
    for (const item of packed.items) {
      allowRetry = allowRetry && item.allowRetry;
      if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
    }
    return { chunk: packed.chunk, allowRetry, completions };
  };

  const 等待可用写入器 = async () => {
    let writer = 获取写入器();
    if (writer) return writer;
    const connectionTask = 获取连接任务?.();
    if (connectionTask) await connectionTask;
    return 获取写入器();
  };

  const drain = async () => {
    if (draining || closed) return;
    draining = true;
    try {
      for (;;) {
        if (closed) break;
        const item = bundle();
        if (!item) break;
        const completions = item.completions || null;
        activeCompletions = completions;
        try {
          let writer = await 等待可用写入器();
          if (closed) break;
          if (!writer) throw new Error(`${名称}: remote writer unavailable`);
          try {
            await writer.write(item.chunk);
          } catch (err) {
            释放写入器?.();
            if (closed) break;
            if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
            await 重试连接();
            if (closed) break;
            writer = 获取写入器();
            if (!writer) throw err;
            await writer.write(item.chunk);
          }
          settleCompletions(completions);
        } catch (err) {
          settleCompletions(completions, err);
          throw err;
        } finally {
          if (activeCompletions === completions) activeCompletions = null;
        }
      }
    } catch (err) {
      closed = true;
      clear(err);
      log(`[${名称}] 写入失败: ${err?.message || err}`);
      try {
        关闭连接?.(err);
      } catch (_) {}
    } finally {
      draining = false;
      if (!closed && !grain.为空) drain();
      else resolveIdle();
    }
  };

  const enqueue = (data, allowRetry = true, waitForFlush = false) => {
    if (closed) return false;
    // 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
    // 已建立会话的重拨阶段则先收纳，drain 会等待新 writer，避免数据被误当成首包。
    if (!获取写入器() && !获取连接任务?.()) return false;
    const chunk = 数据转Uint8Array(data);
    if (!chunk.byteLength) return true;
    const nextBytes = grain.字节数 + chunk.byteLength;
    const nextItems = grain.条目数 + 1;
    if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
      closed = true;
      const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), {
        isQueueOverflow: true,
      });
      clear(err);
      log(`[${名称}] 队列超限，关闭连接`);
      try {
        关闭连接?.(err);
      } catch (_) {}
      throw err;
    }
    let completionPromise = null;
    let completions = null;
    if (waitForFlush) {
      completions = [];
      completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
    }
    grain.收纳({ chunk, allowRetry, completions });
    if (!draining) drain();
    return waitForFlush ? completionPromise.then(() => true) : true;
  };

  return {
    写入(data, allowRetry = true) {
      return enqueue(data, allowRetry, false);
    },
    写入并等待(data, allowRetry = true) {
      return enqueue(data, allowRetry, true);
    },
    async 等待空() {
      if (!grain.字节数 && !draining) return;
      await new Promise((resolve) => idleResolvers.push(resolve));
    },
    清空() {
      closed = true;
      clear();
    },
  };
}
