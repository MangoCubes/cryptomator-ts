import { jest } from '@jest/globals';
import { TextEncoder } from 'util';

global.TextEncoder = TextEncoder

jest.setTimeout(50000000);