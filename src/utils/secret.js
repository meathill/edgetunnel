export function base64SecretEncode(plaintext, secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  const key = encoder.encode(secret);
  const mixed = new Uint8Array(data.length);

  for (let i = 0; i < data.length; i++) {
    mixed[i] = data[i] ^ key[i % key.length];
  }

  // 将 Uint8Array 转换为可被 btoa 处理的字符串
  let binary = '';
  for (let i = 0; i < mixed.length; i++) {
    binary += String.fromCharCode(mixed[i]);
  }
  return btoa(binary);
}

export function base64SecretDecode(encoded, secret) {
  const binary = atob(encoded);
  const mixed = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    mixed[i] = binary.charCodeAt(i);
  }

  const encoder = new TextEncoder();
  const key = encoder.encode(secret);
  const data = new Uint8Array(mixed.length);

  for (let i = 0; i < mixed.length; i++) {
    data[i] = mixed[i] ^ key[i % key.length];
  }

  const decoder = new TextDecoder();
  return decoder.decode(data);
}
