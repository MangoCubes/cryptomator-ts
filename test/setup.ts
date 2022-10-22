import { jest } from '@jest/globals';
import webcrypto from 'crypto';
import { TextEncoder } from 'util';

global.TextEncoder = TextEncoder
global.crypto = webcrypto.webcrypto as any

jest.setTimeout(50000000);