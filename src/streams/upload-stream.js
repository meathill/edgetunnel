import { 上行合包目标字节 } from '../state.js';
import { 数据转Uint8Array } from '../utils/bytes.js';
export function 创建上行Grain合包流(目标字节 = 上行合包目标字节) {
  const identity =
    typeof IdentityTransformStream !== 'undefined' ? new IdentityTransformStream() : new TransformStream();
  const writer = identity.writable.getWriter();
  const 缓冲 = new Uint8Array(目标字节);
  let 缓冲长度 = 0;
  let 定时器 = null;
  let 在途写 = null;
  let 冲刷链 = Promise.resolve();

  const 清理定时器 = () => {
    if (定时器) {
      clearTimeout(定时器);
      定时器 = null;
    }
  };

  const 串行写 = async (chunk) => {
    if (在途写) await 在途写;
    在途写 = writer.write(chunk);
    try {
      await 在途写;
    } finally {
      在途写 = null;
    }
  };

  const 冲刷 = async () => {
    if (缓冲长度) {
      const chunk = 缓冲.slice(0, 缓冲长度);
      缓冲长度 = 0;
      await 串行写(chunk);
    }
  };

  const 排队冲刷 = () => {
    冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => {});
  };

  const 启动定时器 = () => {
    if (定时器) return;
    定时器 = setTimeout(() => {
      定时器 = null;
      排队冲刷();
    }, 1);
  };

  return {
    readable: identity.readable,
    写入: async (chunk) => {
      const data = 数据转Uint8Array(chunk);
      if (!data.byteLength) return;
      if (data.byteLength >= 目标字节) {
        清理定时器();
        if (缓冲长度) await 冲刷();
        await 串行写(data);
        return;
      }
      if (缓冲长度 + data.byteLength >= 目标字节) {
        const output = new Uint8Array(缓冲长度 + data.byteLength);
        output.set(缓冲.subarray(0, 缓冲长度), 0);
        output.set(data, 缓冲长度);
        缓冲长度 = 0;
        清理定时器();
        await 串行写(output);
      } else {
        缓冲.set(data, 缓冲长度);
        缓冲长度 += data.byteLength;
        启动定时器();
      }
    },
    结束: async () => {
      清理定时器();
      try {
        await 冲刷链;
        await 冲刷();
        await writer.close();
      } finally {
        try {
          writer.releaseLock();
        } catch (e) {}
      }
    },
  };
}
