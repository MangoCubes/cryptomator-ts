import crypto from 'crypto';
import { TextEncoder } from 'util';

global.TextEncoder = TextEncoder

Object.defineProperty(global, 'crypto', {
	value: {
		subtle: crypto.webcrypto.subtle
	}
}); // I still don't understand why declaring TextEncoder and subtle crypto for testing env needs to be different...