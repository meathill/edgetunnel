export function 失效TCP连接世代(remoteConnWrapper) {
  if (!remoteConnWrapper) return;
  remoteConnWrapper.generation =
    (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
  const socket = remoteConnWrapper.socket;
  remoteConnWrapper.socket = null;
  remoteConnWrapper.downlinkController = null;
  remoteConnWrapper.downlinkDrain = Promise.resolve();
  try {
    socket?.close?.();
  } catch (e) {}
}

export function 开始TCP连接世代(remoteConnWrapper) {
  if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
  const generation = ++remoteConnWrapper.generation;
  const previousSocket = remoteConnWrapper.socket;
  remoteConnWrapper.socket = null;
  const previousDownlink = remoteConnWrapper.downlinkController;
  remoteConnWrapper.downlinkController = null;
  const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
  let currentDrain;
  try {
    currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve();
  } catch (error) {
    currentDrain = Promise.reject(error);
  }
  const downlinkDrain = Promise.all([previousDrain, currentDrain]);
  // Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
  downlinkDrain.catch(() => {});
  remoteConnWrapper.downlinkDrain = downlinkDrain;
  try {
    previousSocket?.close?.();
  } catch (e) {}
  return { generation, downlinkDrain };
}
