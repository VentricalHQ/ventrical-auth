import { createMemoryStore } from './helpers/memory-store.js';
import { storeContract } from './store-contract.js';

storeContract('memory', async () => {
  const store = createMemoryStore();
  return {
    store,
    suspend: async (userId) => { store.suspend(userId); },
    moveIdentity: async (p, s, to) => { store.moveIdentity(p, s, to); },
    setCreatedAt: async (h, d) => { store.sessions.get(h)!.createdAt = d; },
  };
});
