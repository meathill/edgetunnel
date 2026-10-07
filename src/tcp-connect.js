import { connect } from 'cloudflare:sockets';
// 使用官方公开接口，避免依赖 request.fetcher 内部实现。
export function 创建请求TCP连接器() {
  return (options, init) => {
    const socket = init === undefined ? connect(options) : connect(options, init);
    // 竞速失败或握手失败时，调用方只等待 opened，closed 的拒绝也必须消费。
    socket.closed?.catch(() => {});
    return socket;
  };
}
