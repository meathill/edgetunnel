import { state } from '../state.js';

/**
 * @param  {...any} args
 */
export function log(...args) {
	if (state.调试日志打印) console.log(...args);
}
