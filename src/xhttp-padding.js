export const HPACKHuffman码长 = [
  13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28,
  28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6,
  5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23,
  22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22,
  23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26,
  20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27,
  27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27,
  27, 27, 27, 26, 30,
];

export function 获取叉HTTPPadding标识(yourUUID) {
  return { 头: yourUUID.slice(1, 7), 键: '_' + yourUUID.slice(25, 31) };
}

export function 计算HPACKHuffman字节长度(字符串) {
  const 字节 = new TextEncoder().encode(字符串);
  let 总位数 = 0;
  for (let i = 0; i < 字节.length; i++) {
    总位数 += HPACKHuffman码长[字节[i]];
  }
  return Math.ceil(总位数 / 8);
}

export function 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键) {
  const 头值 = request.headers.get(本机Padding头);
  if (头值) {
    try {
      const 解析URL = new URL(头值, 'https://x.invalid');
      const 查询值 = 解析URL.searchParams.get(本机Padding键);
      if (查询值) return 查询值;
    } catch (e) {}
    return 头值;
  }
  const 请求URL = new URL(request.url);
  return 请求URL.searchParams.get(本机Padding键) || '';
}

export function 校验叉HTTPPadding(request, 本机Padding头, 本机Padding键) {
  const padding值 = 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键);
  if (!padding值) return true;
  const huffman长度 = 计算HPACKHuffman字节长度(padding值);
  return huffman长度 >= 98 && huffman长度 <= 1002;
}

export const 叉HTTPBase62字符集 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export function 生成叉HTTPPadding串(长度) {
  const 字符集长度 = 叉HTTPBase62字符集.length;
  let 结果 = '';
  for (let i = 0; i < 长度; i++) {
    结果 += 叉HTTPBase62字符集[Math.floor(Math.random() * 字符集长度)];
  }
  return 结果;
}
