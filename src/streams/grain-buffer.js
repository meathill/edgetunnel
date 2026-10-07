export function 创建Grain收纳器(容量, 复制合包结果 = false) {
  let 队列 = [];
  let 头 = 0;
  let 字节数 = 0;
  let 合包缓冲 = null;

  const 为空 = () => 头 >= 队列.length;
  const 压缩 = () => {
    if (头 > 32 && 头 * 2 >= 队列.length) {
      队列 = 队列.slice(头);
      头 = 0;
    }
  };
  const 取出 = () => {
    if (为空()) return null;
    const item = 队列[头];
    队列[头++] = undefined;
    字节数 -= item.chunk.byteLength;
    压缩();
    return item;
  };

  return {
    get 字节数() {
      return 字节数;
    },
    get 条目数() {
      return 队列.length - 头;
    },
    get 为空() {
      return 为空();
    },
    清空(处理项目 = null) {
      if (处理项目) {
        for (let i = 头; i < 队列.length; i++) {
          if (队列[i]) 处理项目(队列[i]);
        }
      }
      队列 = [];
      头 = 0;
      字节数 = 0;
    },
    收纳(item) {
      if (!item?.chunk?.byteLength) return false;
      队列.push(item);
      字节数 += item.chunk.byteLength;
      return true;
    },
    合包() {
      const first = 取出();
      if (!first) return null;
      const items = [first];
      if (为空() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

      let totalBytes = first.chunk.byteLength;
      let end = 头;
      while (end < 队列.length) {
        const nextBytes = totalBytes + 队列[end].chunk.byteLength;
        if (nextBytes > 容量) break;
        totalBytes = nextBytes;
        end++;
      }
      if (end === 头) return { chunk: first.chunk, items };

      const output = (合包缓冲 ||= new Uint8Array(容量));
      output.set(first.chunk, 0);
      let offset = first.chunk.byteLength;
      while (头 < end) {
        const next = 队列[头];
        队列[头++] = undefined;
        字节数 -= next.chunk.byteLength;
        items.push(next);
        output.set(next.chunk, offset);
        offset += next.chunk.byteLength;
      }
      压缩();
      const bundled = output.subarray(0, totalBytes);
      return { chunk: 复制合包结果 ? bundled.slice() : bundled, items };
    },
  };
}
