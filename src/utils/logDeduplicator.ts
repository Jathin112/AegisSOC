import { NormalizedAuthLog } from '../types';

/**
 * Deterministic hash generator for offline log deduplication
 */
export function generateLogHash(log: Partial<NormalizedAuthLog>): string {
  const normUser = (log.user || '').toLowerCase().trim();
  const normHost = (log.host || '').toLowerCase().trim();
  const normIp = (log.ip || '').trim();
  const normAction = (log.action || '').toUpperCase().trim();
  const normTimestamp = log.timestamp || '';
  const normReason = (log.failureReason || '').toLowerCase().trim();

  const rawKey = `${normTimestamp}|${normUser}|${normIp}|${normHost}|${normAction}|${normReason}`;
  
  // Fast 32-bit FNV-1a hash
  let hash = 2166136261;
  for (let i = 0; i < rawKey.length; i++) {
    hash ^= rawKey.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `EVT-${(hash >>> 0).toString(16).padStart(8, '0').toUpperCase()}`;
}

export interface DeduplicationResult {
  uniqueLogs: NormalizedAuthLog[];
  duplicateCount: number;
  duplicateGroups: Record<string, number>;
}

export function deduplicateLogs(logs: NormalizedAuthLog[]): DeduplicationResult {
  const seenMap = new Map<string, NormalizedAuthLog>();
  let duplicateCount = 0;
  const duplicateGroups: Record<string, number> = {};

  for (const log of logs) {
    const hash = log.hash || generateLogHash(log);
    log.hash = hash;

    if (seenMap.has(hash)) {
      duplicateCount++;
      const existing = seenMap.get(hash)!;
      existing.duplicateCount = (existing.duplicateCount || 1) + 1;
      log.isDuplicate = true;
      duplicateGroups[hash] = (duplicateGroups[hash] || 1) + 1;
    } else {
      log.isDuplicate = false;
      log.duplicateCount = 1;
      seenMap.set(hash, log);
    }
  }

  return {
    uniqueLogs: Array.from(seenMap.values()),
    duplicateCount,
    duplicateGroups
  };
}
