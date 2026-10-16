import { NormalizedAuthLog, UserBaseline, TrainingPeriodConfig } from '../types';

/**
 * Extracts /24 subnet from IPv4 address or prefix for IPv6
 */
export function extractSubnet(ip: string): string {
  if (!ip) return 'UNKNOWN';
  const ipv4Parts = ip.split('.');
  if (ipv4Parts.length === 4) {
    return `${ipv4Parts[0]}.${ipv4Parts[1]}.${ipv4Parts[2]}.0/24`;
  }
  return ip;
}

export interface BaselineLearningResult {
  baselines: Map<string, UserBaseline>;
  trainingCutoffTimestamp: string;
  trainingLogCount: number;
  evaluationLogCount: number;
  totalUsersLearned: number;
}

export function learnBaselines(
  logs: NormalizedAuthLog[],
  config: TrainingPeriodConfig
): BaselineLearningResult {
  if (logs.length === 0) {
    return {
      baselines: new Map(),
      trainingCutoffTimestamp: '',
      trainingLogCount: 0,
      evaluationLogCount: 0,
      totalUsersLearned: 0
    };
  }

  // Sort logs chronologically to properly evaluate training vs evaluation periods
  const sortedLogs = [...logs].sort((a, b) => a.epochMs - b.epochMs);
  const minTime = sortedLogs[0].epochMs;
  const maxTime = sortedLogs[sortedLogs.length - 1].epochMs;

  let trainingLogs: NormalizedAuthLog[] = [];
  let evaluationLogs: NormalizedAuthLog[] = [];
  let cutoffEpoch = minTime;

  if (config.mode === 'PERCENTAGE') {
    const pct = Math.max(5, Math.min(95, config.percentage || 50));
    const splitIndex = Math.floor((sortedLogs.length * pct) / 100);
    trainingLogs = sortedLogs.slice(0, splitIndex);
    evaluationLogs = sortedLogs.slice(splitIndex);
    cutoffEpoch = trainingLogs[trainingLogs.length - 1]?.epochMs || minTime;
  } else if (config.mode === 'DATE_RANGE') {
    const startMs = config.startDate ? new Date(config.startDate).getTime() : minTime;
    const endMs = config.endDate ? new Date(config.endDate).getTime() : minTime + (maxTime - minTime) * 0.5;
    cutoffEpoch = endMs;
    trainingLogs = sortedLogs.filter(l => l.epochMs >= startMs && l.epochMs <= endMs);
    evaluationLogs = sortedLogs.filter(l => l.epochMs > endMs);
  } else if (config.mode === 'FIRST_N_DAYS') {
    const days = config.firstNDays || 7;
    cutoffEpoch = minTime + days * 24 * 60 * 60 * 1000;
    trainingLogs = sortedLogs.filter(l => l.epochMs <= cutoffEpoch);
    evaluationLogs = sortedLogs.filter(l => l.epochMs > cutoffEpoch);
  }

  // Tag each log whether it falls within training period
  sortedLogs.forEach(l => {
    l.inTrainingPeriod = l.epochMs <= cutoffEpoch;
  });

  const baselines = new Map<string, UserBaseline>();

  // Learn per-user baselines from trainingLogs
  for (const log of trainingLogs) {
    const userKey = log.user.toLowerCase().trim();
    if (!userKey) continue;

    let baseline = baselines.get(userKey);
    if (!baseline) {
      baseline = {
        user: log.user,
        totalEvents: 0,
        usualHours: [],
        hourDistribution: {},
        usualIPs: [],
        usualSubnets: [],
        usualLocations: [],
        usualHosts: [],
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        trainingLogsCount: 0
      };
      baselines.set(userKey, baseline);
    }

    baseline.totalEvents++;
    baseline.trainingLogsCount++;
    baseline.lastSeen = log.timestamp;

    // Diurnal hour (UTC hour 0-23)
    const hour = log.dateObj.getUTCHours();
    baseline.hourDistribution[hour] = (baseline.hourDistribution[hour] || 0) + 1;

    // Usual IP
    if (log.ip && !baseline.usualIPs.includes(log.ip)) {
      baseline.usualIPs.push(log.ip);
    }

    // Subnet
    const subnet = extractSubnet(log.ip);
    if (subnet && !baseline.usualSubnets.includes(subnet)) {
      baseline.usualSubnets.push(subnet);
    }

    // Location
    if (log.location && !baseline.usualLocations.includes(log.location)) {
      baseline.usualLocations.push(log.location);
    }

    // Host
    const hostNorm = log.host.toUpperCase().trim();
    if (hostNorm && !baseline.usualHosts.includes(hostNorm)) {
      baseline.usualHosts.push(hostNorm);
    }
  }

  // Finalize usualHours (any hour with >= 1 event during training is known; or hours accounting for >2% activity)
  for (const baseline of baselines.values()) {
    baseline.usualHours = Object.keys(baseline.hourDistribution).map(Number).sort((a, b) => a - b);
  }

  return {
    baselines,
    trainingCutoffTimestamp: new Date(cutoffEpoch).toISOString(),
    trainingLogCount: trainingLogs.length,
    evaluationLogCount: evaluationLogs.length,
    totalUsersLearned: baselines.size
  };
}
