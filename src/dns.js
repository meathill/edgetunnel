import { log } from './utils/log.js';
import { 整理成数组 } from './utils/format.js';
export const DoH缓存 = {};

export const DoH缓存最大条目 = 256;

export const DoH记录类型映射 = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };

export async function DoH查询(域名, 记录类型, DoH解析服务 = 'https://cloudflare-dns.com/dns-query') {
  const 规范化域名 = String(域名 || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
  const 规范化记录类型 = String(记录类型 || '')
    .trim()
    .toUpperCase();
  const 缓存键 = `${DoH解析服务}:${规范化域名}:${规范化记录类型}`;
  const qtype = DoH记录类型映射[规范化记录类型] || 1;
  const 当前时间戳 = Date.now();
  const 现缓存项 = DoH缓存[缓存键];
  if (现缓存项 && 当前时间戳 < 现缓存项.过期时间) {
    log(`[DoH查询] 命中缓存 ${域名} ${记录类型} via ${DoH解析服务}`);
    return 现缓存项.data.map((data) => ({ type: qtype, data }));
  }
  const 开始时间 = performance.now();
  log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
  try {
    // 记录类型字符串转数值
    // 编码域名为 DNS wire format labels
    const 编码域名 = (name) => {
      const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
      const bufs = [];
      for (const label of parts) {
        const enc = new TextEncoder().encode(label);
        bufs.push(new Uint8Array([enc.length]), enc);
      }
      bufs.push(new Uint8Array([0]));
      const total = bufs.reduce((s, b) => s + b.length, 0);
      const result = new Uint8Array(total);
      let off = 0;
      for (const b of bufs) {
        result.set(b, off);
        off += b.length;
      }
      return result;
    };

    // 构建 DNS 查询报文
    const qname = 编码域名(规范化域名);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
    qview.setUint16(2, 0x0100); // Flags: RD=1 (递归查询)
    qview.setUint16(4, 1); // QDCOUNT
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

    // 通过 POST 发送 dns-message 请求
    log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
    const response = await fetch(DoH解析服务, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        Accept: 'application/dns-message',
      },
      body: query,
    });
    if (!response.ok) {
      console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
      return [];
    }

    // 解析 DNS 响应报文
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

    // 解析域名（处理指针压缩）
    const 解析域名 = (pos) => {
      const labels = [];
      let p = pos,
        jumped = false,
        endPos = -1,
        safe = 128;
      while (p < buf.length && safe-- > 0) {
        const len = buf[p];
        if (len === 0) {
          if (!jumped) endPos = p + 1;
          break;
        }
        if ((len & 0xc0) === 0xc0) {
          if (!jumped) endPos = p + 2;
          p = ((len & 0x3f) << 8) | buf[p + 1];
          jumped = true;
          continue;
        }
        labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
        p += len + 1;
      }
      if (endPos === -1) endPos = p + 1;
      return [labels.join('.'), endPos];
    };

    // 跳过 Question Section
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = 解析域名(offset);
      offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
    }

    // 解析 Answer Section
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = 解析域名(offset);
      offset = /** @type {number} */ (nameEnd);
      const type = dv.getUint16(offset);
      offset += 2;
      offset += 2; // CLASS
      const ttl = dv.getUint32(offset);
      offset += 4;
      const rdlen = dv.getUint16(offset);
      offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;

      let data;
      if (type === 1 && rdlen === 4) {
        // A 记录
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        // AAAA 记录
        const segs = [];
        for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
        data = segs.join(':');
      } else if (type === 16) {
        // TXT 记录 (长度前缀字符串)
        let tOff = 0;
        const parts = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++];
          parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join('');
      } else if (type === 5) {
        // CNAME 记录
        const [cname] = 解析域名(offset - rdlen);
        data = cname;
      } else {
        data = Array.from(rdata)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      answers.push({ name, type, TTL: ttl, data, rdata });
    }
    const 耗时 = (performance.now() - 开始时间).toFixed(2);
    log(
      `[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`,
    );
    // DoH 缓存至少保留 5 分钟，响应 TTL 更长时尊重响应 TTL；空响应使用 5 分钟负缓存
    const 相关记录 = answers.filter((answer) => answer.type === qtype);
    const 最小TTL = 相关记录.length > 0 ? Math.min(...相关记录.map((a) => a.TTL)) : 0;
    const 缓存TTL = Math.max(最小TTL, 5 * 60);
    const 缓存过期时间 = Date.now() + 缓存TTL * 1000;
    const 缓存数据 = 相关记录.map((answer) => answer.data);
    if (缓存数据.length > 0 || answers.length === 0) {
      if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
        const 清理时间戳 = Date.now();
        for (const [缓存条目键, 缓存条目] of Object.entries(DoH缓存)) {
          if (清理时间戳 >= 缓存条目.过期时间) delete DoH缓存[缓存条目键];
        }
        if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
          delete DoH缓存[Object.keys(DoH缓存)[0]];
        }
      }
      DoH缓存[缓存键] = { data: 缓存数据, 过期时间: 缓存过期时间 };
      log(`[DoH查询] 写入缓存 ${域名} ${记录类型} TTL=${缓存TTL}s${缓存数据.length === 0 ? '（空结果）' : ''}`);
    }
    return answers;
  } catch (error) {
    const 耗时 = (performance.now() - 开始时间).toFixed(2);
    console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
    return [];
  }
}

export async function 解析地址端口(
  proxyIP,
  目标域名 = 'dash.cloudflare.com',
  UUID = '00000000-0000-4000-8000-000000000000',
) {
  proxyIP = proxyIP.toLowerCase();
  function 解析地址端口字符串(str) {
    let 地址 = str,
      端口 = 443;
    if (str.includes(']:')) {
      const parts = str.split(']:');
      地址 = parts[0] + ']';
      端口 = parseInt(parts[1], 10) || 端口;
    } else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
      const colonIndex = str.lastIndexOf(':');
      地址 = str.slice(0, colonIndex);
      端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
    }
    return [地址, 端口];
  }

  function 解析TXT反代记录(txtData) {
    return txtData
      .flatMap((data) => {
        if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
        return data
          .replace(/\\010/g, ',')
          .replace(/\n/g, ',')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
      })
      .map((prefix) => 解析地址端口字符串(prefix));
  }

  const 反代IP数组 = await 整理成数组(proxyIP);
  let 所有反代数组 = [];
  const ipv4Regex =
    /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

  // 遍历数组中的每个IP元素进行处理
  for (const singleProxyIP of 反代IP数组) {
    let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

    if (singleProxyIP.includes('.tp')) {
      const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
      if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
    }

    // 判断是否是域名（非IP地址）
    if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
      log(`[反代解析] ${地址} 为IP地址，直接使用`);
      所有反代数组.push([地址, 端口]);
      continue;
    }

    const [txtRecords, aRecords] = await Promise.all([DoH查询(地址, 'TXT'), DoH查询(地址, 'A')]);

    const txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
    const txtAddresses = 解析TXT反代记录(txtData);
    if (txtAddresses.length > 0) {
      log(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
      所有反代数组.push(...txtAddresses);
      continue;
    }

    const ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
    if (ipv4List.length > 0) {
      log(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
      所有反代数组.push(...ipv4List.map((ip) => [ip, 端口]));
      continue;
    }

    const aaaaRecords = await DoH查询(地址, 'AAAA');
    const ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
    if (ipv6List.length > 0) {
      log(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
      所有反代数组.push(...ipv6List.map((ip) => [ip, 端口]));
    } else {
      log(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
      所有反代数组.push([地址, 端口]);
    }
  }
  const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
  const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
  let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
  log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`);
  const 洗牌后 = [...排序后数组].sort(
    () => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5,
  );
  const 解析结果 = 洗牌后.slice(0, 8);
  log(
    `[反代解析] 解析完成 总数: ${解析结果.length}个\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`,
  );
  return 解析结果;
}
