import { 获取叉HTTPPadding标识 } from '../xhttp-padding.js';
import { 随机路径 } from '../utils/path.js';
export function 获取传输协议配置(配置 = {}) {
  const 是gRPC = 配置.传输协议 === 'grpc';
  const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(配置.UUID);
  const 叉混淆JSON = {
    xPaddingObfsMode: true,
    xPaddingMethod: 'tokenish',
    xPaddingPlacement: 'queryInHeader',
    xPaddingHeader: 本机Padding头,
    xPaddingKey: 本机Padding键,
  };
  return {
    type: 是gRPC
      ? 配置.gRPC模式 === 'multi'
        ? 'grpc&mode=multi'
        : 'grpc&mode=gun'
      : 配置.传输协议 === 'xhttp'
        ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(叉混淆JSON))}`
        : 'ws',
    路径字段名: 是gRPC ? 'serviceName' : 'path',
    域名字段名: 是gRPC ? 'authority' : 'host',
  };
}

export function 获取传输路径参数值(配置 = {}, 节点路径 = '/', 作为优选订阅生成器 = false) {
  const 路径值 = 作为优选订阅生成器 ? '/' : 配置.随机路径 ? 随机路径(节点路径) : 节点路径;
  if (配置.传输协议 !== 'grpc') return 路径值;
  return 路径值.split('?')[0] || '/';
}
