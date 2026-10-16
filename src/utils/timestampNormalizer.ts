/**
 * Offline Timestamp Normalizer
 * Ingests diverse datetime formats without external network calls
 * Formats supported: ISO-8601, RFC-2822, YYYY-MM-DD HH:mm:ss, MM/DD/YYYY, DD/MM/YYYY, Epoch (sec/ms)
 */

export interface NormalizedTimestampResult {
  iso: string;
  dateObj: Date;
  epochMs: number;
  isValid: boolean;
  detectedFormat: string;
}

export function normalizeTimestamp(raw: string | number | undefined | null): NormalizedTimestampResult {
  if (raw === undefined || raw === null || raw === '') {
    const fallback = new Date();
    return {
      iso: fallback.toISOString(),
      dateObj: fallback,
      epochMs: fallback.getTime(),
      isValid: false,
      detectedFormat: 'UNKNOWN_EMPTY'
    };
  }

  // Handle number or numeric string (Unix epoch)
  if (typeof raw === 'number' || (/^\d+$/.test(String(raw).trim()))) {
    const num = Number(raw);
    // If < 10000000000, it's seconds, convert to ms
    const ms = num < 10000000000 ? num * 1000 : num;
    const date = new Date(ms);
    if (!isNaN(date.getTime())) {
      return {
        iso: date.toISOString(),
        dateObj: date,
        epochMs: date.getTime(),
        isValid: true,
        detectedFormat: 'UNIX_EPOCH'
      };
    }
  }

  const str = String(raw).trim();

  // Try native Date.parse first
  const nativeParsed = Date.parse(str);
  if (!isNaN(nativeParsed)) {
    const date = new Date(nativeParsed);
    return {
      iso: date.toISOString(),
      dateObj: date,
      epochMs: date.getTime(),
      isValid: true,
      detectedFormat: 'STANDARD_OR_ISO'
    };
  }

  // Custom regex parsing for common syslog and AD formats:
  // e.g. "2026-10-14 08:30:00", "2026/10/14 08:30:00"
  const isoLikeMatch = str.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?(?:\.(\d+))?(?:Z|([+-]\d{2}:?\d{2}))?$/i);
  if (isoLikeMatch) {
    const [_, y, m, d, hh, mm, ss = '0', ms = '0', tz] = isoLikeMatch;
    const isoStr = `${y}-${m.padStart(2, '0')}-${d.padStart(2, '0')}T${hh.padStart(2, '0')}:${mm.padStart(2, '0')}:${ss.padStart(2, '0')}${tz || 'Z'}`;
    const date = new Date(isoStr);
    if (!isNaN(date.getTime())) {
      return {
        iso: date.toISOString(),
        dateObj: date,
        epochMs: date.getTime(),
        isValid: true,
        detectedFormat: 'CUSTOM_ISO_LIKE'
      };
    }
  }

  // e.g. "10/14/2026 08:30:00 AM" or "10/14/2026 14:30:00"
  const usDateMatch = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?\s*(AM|PM)?$/i);
  if (usDateMatch) {
    const [_, month, day, year, rawHours, mins, secs = '0', ampm] = usDateMatch;
    let hours = parseInt(rawHours, 10);
    if (ampm) {
      if (ampm.toUpperCase() === 'PM' && hours < 12) hours += 12;
      if (ampm.toUpperCase() === 'AM' && hours === 12) hours = 0;
    }
    const date = new Date(Date.UTC(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10), hours, parseInt(mins, 10), parseInt(secs, 10)));
    if (!isNaN(date.getTime())) {
      return {
        iso: date.toISOString(),
        dateObj: date,
        epochMs: date.getTime(),
        isValid: true,
        detectedFormat: 'US_FORMAT'
      };
    }
  }

  // Fallback: current time with isValid = false
  const fallbackDate = new Date();
  return {
    iso: fallbackDate.toISOString(),
    dateObj: fallbackDate,
    epochMs: fallbackDate.getTime(),
    isValid: false,
    detectedFormat: 'INVALID_FALLBACK'
  };
}

export function formatUtcDateTime(dateOrIso: Date | string): string {
  const d = typeof dateOrIso === 'string' ? new Date(dateOrIso) : dateOrIso;
  if (isNaN(d.getTime())) return 'Invalid Date';
  return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}
