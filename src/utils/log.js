export function 创建日志器(enabled = false) {
  return (...args) => {
    if (enabled) console.log(...args);
  };
}
export const log = 创建日志器();
