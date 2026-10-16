import Papa from 'papaparse';
import { NormalizedAuthLog, RawAuthLog, AuthAction } from '../types';
import { normalizeTimestamp } from './timestampNormalizer';
import { generateLogHash } from './logDeduplicator';

export interface ParseResult {
  logs: NormalizedAuthLog[];
  errors: string[];
  totalRawRows: number;
  detectedColumns: string[];
}

/**
 * Validates and normalizes source IP telemetry, detecting missing or malformed records
 */
export function validateIpAddress(rawIp: string | undefined): {
  normalizedIp: string;
  status: 'VALID' | 'MISSING' | 'INVALID_FORMAT';
  uncertaintyNotes?: string;
} {
  const trimmed = (rawIp || '').trim();
  if (!trimmed || trimmed === '-' || trimmed === 'N/A' || trimmed.toUpperCase() === 'UNKNOWN' || trimmed === '0.0.0.0') {
    return {
      normalizedIp: 'MISSING_IP',
      status: 'MISSING',
      uncertaintyNotes: 'Source IP telemetry is missing from authentication record. Geolocation and origin-based heuristics carry high uncertainty.'
    };
  }

  // Check IPv4 format: 4 octets each 0-255
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = trimmed.match(ipv4Regex);
  if (!match) {
    return {
      normalizedIp: trimmed,
      status: 'INVALID_FORMAT',
      uncertaintyNotes: `Source IP '${trimmed}' has an invalid format. Cannot reliably derive CIDR subnet or geographic attribution.`
    };
  }

  const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
  const allValid = octets.every(o => o >= 0 && o <= 255);
  if (!allValid) {
    return {
      normalizedIp: trimmed,
      status: 'INVALID_FORMAT',
      uncertaintyNotes: `Source IP '${trimmed}' has out-of-range octets (>255). Telemetry is corrupted or malformed.`
    };
  }

  return {
    normalizedIp: trimmed,
    status: 'VALID'
  };
}

export function parseAuthLogsCsv(csvContent: string, companyId: string = 'COMP-001'): ParseResult {
  const errors: string[] = [];
  const logs: NormalizedAuthLog[] = [];

  const parsed = Papa.parse<RawAuthLog>(csvContent, {
    header: true,
    skipEmptyLines: 'greedy',
    dynamicTyping: false
  });

  if (parsed.errors && parsed.errors.length > 0) {
    parsed.errors.forEach(e => errors.push(`CSV Row ${e.row}: ${e.message}`));
  }

  const detectedColumns = parsed.meta.fields || [];

  parsed.data.forEach((row, index) => {
    // Normalization helper for varied column naming conventions
    const getVal = (candidates: string[]): string => {
      for (const c of candidates) {
        if (row[c] !== undefined && row[c] !== null && String(row[c]).trim() !== '') {
          return String(row[c]).trim();
        }
        // Case-insensitive check
        const matchKey = Object.keys(row).find(k => k.toLowerCase() === c.toLowerCase());
        if (matchKey && row[matchKey] !== undefined && row[matchKey] !== null && String(row[matchKey]).trim() !== '') {
          return String(row[matchKey]).trim();
        }
      }
      return '';
    };

    const rawTimestamp = getVal(['timestamp', 'time', 'datetime', 'date', 'event_time', 'log_time', '@timestamp']);
    const rawUser = getVal(['user', 'username', 'account', 'user_id', 'target_user', 'user_principal_name']);
    const rawIp = getVal(['ip', 'source_ip', 'ip_address', 'src_ip', 'client_ip', 'sourceip']);
    const rawHost = getVal(['host', 'hostname', 'computer_name', 'target_host', 'server', 'workstation', 'device']);
    const rawAction = getVal(['action', 'status', 'result', 'event', 'outcome', 'auth_result']);
    const rawReason = getVal(['reason', 'failure_reason', 'message', 'error_code', 'sub_status', 'sub_status_code']);
    const rawLocation = getVal(['location', 'geo', 'country', 'city', 'region', 'source_location']);
    const rawUserAgent = getVal(['user_agent', 'useragent', 'client_app', 'device_type']);

    if (!rawUser && !rawIp && !rawHost) {
      // Empty or invalid row
      return;
    }

    const timeResult = normalizeTimestamp(rawTimestamp);
    
    // Normalize Action to 'SUCCESS' | 'FAILURE'
    let action: AuthAction = 'SUCCESS';
    const actionLower = rawAction.toLowerCase();
    if (
      actionLower.includes('fail') ||
      actionLower.includes('error') ||
      actionLower.includes('denied') ||
      actionLower.includes('reject') ||
      actionLower.includes('blocked') ||
      actionLower === '4625' || // Windows Event ID 4625 = Failed Logon
      actionLower === '0'
    ) {
      action = 'FAILURE';
    } else if (
      actionLower.includes('succ') ||
      actionLower.includes('allow') ||
      actionLower.includes('permit') ||
      actionLower === '4624' || // Windows Event ID 4624 = Successful Logon
      actionLower === '1'
    ) {
      action = 'SUCCESS';
    } else if (rawReason.toLowerCase().includes('fail') || rawReason.toLowerCase().includes('bad') || rawReason.toLowerCase().includes('lock')) {
      action = 'FAILURE';
    }

    let normalizedReason = rawReason || (action === 'FAILURE' ? 'Authentication Failed' : 'Login successful');
    if (normalizedReason.toLowerCase() === 'logon successful' || normalizedReason.toLowerCase() === 'logon') {
      normalizedReason = 'Login successful';
    }

    const ipValidation = validateIpAddress(rawIp);
    const isUncertain = ipValidation.status !== 'VALID';

    let location = rawLocation;
    if (!location) {
      if (ipValidation.status === 'VALID') {
        const ip = ipValidation.normalizedIp;
        location = (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) 
          ? 'Internal Corporate LAN' 
          : 'External IP';
      } else {
        location = 'Unknown / Unverified Location';
      }
    }

    const logItem: NormalizedAuthLog = {
      id: `LOG-${(index + 1).toString().padStart(5, '0')}`,
      rawTimestamp: rawTimestamp || 'N/A',
      timestamp: timeResult.iso,
      dateObj: timeResult.dateObj,
      epochMs: timeResult.epochMs,
      user: rawUser || 'UNKNOWN_USER',
      ip: ipValidation.normalizedIp,
      host: (rawHost || 'UNKNOWN_HOST').toUpperCase(),
      action,
      failureReason: normalizedReason,
      location,
      userAgent: rawUserAgent,
      hash: '',
      isDuplicate: false,
      duplicateCount: 1,
      inTrainingPeriod: false,
      companyId,
      ipValidationStatus: ipValidation.status,
      telemetryUncertainty: isUncertain,
      uncertaintyNotes: ipValidation.uncertaintyNotes
    };

    logItem.hash = generateLogHash(logItem);
    logs.push(logItem);
  });

  return {
    logs,
    errors,
    totalRawRows: parsed.data.length,
    detectedColumns
  };
}
