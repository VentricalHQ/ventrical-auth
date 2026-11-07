import { createMemoryStore } from './helpers/memory-store.js';
import { twoFactorConcurrencyContract } from './two-factor-concurrency.js';

twoFactorConcurrencyContract('memory', async () => ({ store: createMemoryStore() }));
