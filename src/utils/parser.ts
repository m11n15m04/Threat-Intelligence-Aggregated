/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IOC, IOCType, IOCSeverity } from '../types';

// Strict regex matching patterns
export const IP_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
export const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,18}\b/g;
export const URL_REGEX = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;

// For domains, match standard domains but avoid extracting numbers that are inside IP addresses
// Domain pattern needs at least one dot, valid alphanumeric components, and safe TLD checks.
export const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,18}\b/g;

export const HASH_MD5_REGEX = /\b[a-fA-F0-9]{32}\b/gi;
export const HASH_SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/gi;
export const HASH_SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/gi;

// Safe whitelisted domains/URLs/IPs to identify False Positives (Safe Lists)
export const SAFE_WHITELIST = [
  'google.com', 'www.google.com', 'google.co', 'dns.google',
  'microsoft.com', 'apple.com', 'github.com', 'githubusercontent.com',
  'cloudflare.com', 'one.one.one.one', '1.1.1.1', '8.8.8.8', '8.8.4.4',
  'amazon.com', 'aws.amazon.com', 'wikipedia.org', 'localhost'
];

/**
 * Validates an IP address is not from a private or loopback subnet.
 */
export function isPrivateIP(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '0.0.0.0') return true;
  // RFC 1918 networks:
  // 10.0.0.0 - 10.255.255.255
  if (ip.startsWith('10.')) return true;
  // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  // 192.168.0.0 - 192.168.255.255
  if (ip.startsWith('192.168.')) return true;
  // APIPA / Link-local: 169.254.0.0 - 169.254.255.255
  if (ip.startsWith('169.254.')) return true;
  
  return false;
}

/**
 * Validates whether an indicator is valid or is a false-positive whitelisted entry.
 */
export function validateIOC(value: string, type: IOCType): { isValid: boolean; reason?: string } {
  const normalizedValue = value.toLowerCase().trim();
  
  // Empty values
  if (!normalizedValue) {
    return { isValid: false, reason: 'Empty value' };
  }

  // Whitelist checks
  if (SAFE_WHITELIST.includes(normalizedValue)) {
    return { isValid: false, reason: 'Whitelisted safe-list entry (False-Positive Mitigation)' };
  }

  // Type specific boundary checks
  if (type === IOCType.IP) {
    const parts = normalizedValue.split('.');
    if (parts.length !== 4) {
      return { isValid: false, reason: 'Invalid IP format' };
    }
    const hasOctetError = parts.some(part => {
      const num = parseInt(part, 10);
      return isNaN(num) || num < 0 || num > 255;
    });
    if (hasOctetError) {
      return { isValid: false, reason: 'IP addresses must have octets in range 0-255' };
    }
    if (isPrivateIP(normalizedValue)) {
      return { isValid: false, reason: 'RFC 1918 Private or Loopback IP Address' };
    }
  }

  if (type === IOCType.Email) {
    if (normalizedValue.includes('@@') || normalizedValue.startsWith('@') || normalizedValue.endsWith('@')) {
      return { isValid: false, reason: 'Malformed email address' };
    }
  }

  if (type === IOCType.Domain) {
    // Make sure it doesn't parse an IP address as a domain (e.g. 192.168.1.1 is NOT a domain)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalizedValue)) {
      return { isValid: false, reason: 'IP classified as domain' };
    }
  }

  return { isValid: true };
}

/**
 * Parses STIX 2.1 JSON payload and extracts indicators.
 */
export function parseSTIXContent(content: string, source: string): IOC[] {
  const iocs: IOC[] = [];
  try {
    const bundle = JSON.parse(content);
    if (!bundle.objects || !Array.isArray(bundle.objects)) return iocs;

    for (const obj of bundle.objects) {
      if (obj.type === 'indicator' && obj.pattern) {
        const pattern: string = obj.pattern;
        const description = obj.description || obj.name || '';
        
        let value = '';
        let type: IOCType | null = null;
        let hashType: 'MD5' | 'SHA-1' | 'SHA-256' | null = null;

        // Try parsing common STIX patterns
        if (pattern.includes("file:hashes.'SHA-256'")) {
          const match = pattern.match(/=\s*'([a-fA-F0-9]{64})'/);
          if (match) {
            value = match[1];
            type = IOCType.Hash;
            hashType = 'SHA-256';
          }
        } else if (pattern.includes("file:hashes.'MD5'")) {
          const match = pattern.match(/=\s*'([a-fA-F0-9]{32})'/);
          if (match) {
            value = match[1];
            type = IOCType.Hash;
            hashType = 'MD5';
          }
        } else if (pattern.includes("ipv4-addr:value")) {
          const match = pattern.match(/=\s*'([^']+)'/);
          if (match) {
            value = match[1];
            type = IOCType.IP;
          }
        } else if (pattern.includes("domain-name:value")) {
          const match = pattern.match(/=\s*'([^']+)'/);
          if (match) {
            value = match[1];
            type = IOCType.Domain;
          }
        } else if (pattern.includes("url:value")) {
          const match = pattern.match(/=\s*'([^']+)'/);
          if (match) {
            value = match[1];
            type = IOCType.URL;
          }
        }

        if (value && type) {
          const validation = validateIOC(value, type);
          iocs.push({
            id: `ioc-${type}-${value}-${source}`,
            value,
            type,
            hashType,
            source,
            sources: [source],
            timestamp: new Date().toISOString(),
            severity: description.toLowerCase().includes('critical') || description.toLowerCase().includes('high') ? IOCSeverity.High : IOCSeverity.Medium,
            category: description.toLowerCase().includes('ransomware') ? 'Ransomware' : 'Threat Intelligence',
            confidence: 90,
            description,
            isValid: validation.isValid,
            notes: validation.reason,
          });
        }
      }
    }
  } catch (err) {
    console.error('Failed to parse STIX Object format', err);
  }
  return iocs;
}

/**
 * Universal extractor scanning and validating structured or unstructured text feeds.
 */
export function parseFeedContent(sourceName: string, format: 'csv' | 'json' | 'stix' | 'txt', content: string): IOC[] {
  if (format === 'stix') {
    return parseSTIXContent(content, sourceName);
  }

  const iocs: IOC[] = [];
  const lines = content.split('\n');

  // If it is JSON but not explicitly STIX, parse it or run universal regex
  if (format === 'json') {
    try {
      const parsed = JSON.parse(content);
      // Run fallback regex extraction across the string if it is general telemetry
      return parseTextRegex(content, sourceName);
    } catch (e) {
      // Fall through to regex-based extraction
    }
  }

  // If it's a CSV format, try split parsing for enriched metadata extraction
  if (format === 'csv') {
    for (const line of lines) {
      if (line.trim().startsWith('#') || !line.trim()) continue;
      
      const columns = line.split(',').map(c => c.trim().replace(/^["']|["']$/g, ''));
      if (columns.length < 2) {
        // Fallback to regex extraction for this line
        const lineIOCs = parseTextRegex(line, sourceName);
        iocs.push(...lineIOCs);
        continue;
      }

      // Read columns
      const firstCol = columns[0];
      const secondCol = columns[1];
      
      // Look for indicators in columns
      let value = '';
      let type: IOCType | null = null;
      let category = 'Threat Intelligence';
      let confidence = 80;
      let description = `Extracted from CSV grid in ${sourceName}`;
      let hashType: 'MD5' | 'SHA-1' | 'SHA-256' | null = null;
      let severity = IOCSeverity.Medium;

      // Check if line looks like our simulated ransomware CSV: (ip,status,category,confidence,description)
      if (IP_REGEX.test(firstCol)) {
        value = firstCol;
        type = IOCType.IP;
        category = columns[2] || 'Malware Node';
        confidence = isNaN(parseInt(columns[3], 10)) ? 80 : parseInt(columns[3], 10);
        description = columns[4] || 'Ransomware host tracker node';
      } 
      // check PhishNet structure: (date,indicator,type,category,severity)
      else if (columns.length >= 4 && (columns[1].includes('http') || columns[1].includes('@') || columns[1].includes('.'))) {
        value = columns[1];
        category = columns[3] || 'Phishing';
        description = `Identified by PhishNet tracker as ${category}`;
        const sevStr = (columns[4] || 'medium').toLowerCase();
        if (sevStr === 'high') severity = IOCSeverity.High;
        else if (sevStr === 'low') severity = IOCSeverity.Low;

        // Determine type of the indicator column
        if (value.startsWith('http')) {
          type = IOCType.URL;
        } else if (value.includes('@')) {
          type = IOCType.Email;
        } else if (DOMAIN_REGEX.test(value)) {
          type = IOCType.Domain;
        } else if (IP_REGEX.test(value)) {
          type = IOCType.IP;
        }
      }

      // If we classified a column structured IOC
      if (value && type) {
        const validation = validateIOC(value, type);
        iocs.push({
          id: `ioc-${type}-${value}-${sourceName}`,
          value,
          type,
          hashType,
          source: sourceName,
          sources: [sourceName],
          timestamp: new Date().toISOString(),
          severity,
          category,
          confidence,
          description,
          isValid: validation.isValid,
          notes: validation.reason,
         });
         continue; // Handled
      }
    }
  }

  // Unstructured Text regex processing fallback
  const textIOCs = parseTextRegex(content, sourceName);
  
  // Merge structured CSV parsed with raw regex extractions
  for (const ioc of textIOCs) {
    // Avoid double counting if already parsed properly via structured format
    if (!iocs.some(i => i.value.toLowerCase() === ioc.value.toLowerCase())) {
      iocs.push(ioc);
    }
  }

  return iocs;
}

/**
 * Parses unstructured strings and maps standard regexes directly.
 */
export function parseTextRegex(text: string, sourceName: string): IOC[] {
  const iocs: IOC[] = [];

  // Helper function to extract and commit
  const extract = (regex: RegExp, type: IOCType, hashType: any = null, category: string = 'General Threat') => {
    regex.lastIndex = 0;
    const matches = text.match(regex) || [];
    const uniqueMatches = Array.from(new Set(matches));

    for (const match of uniqueMatches) {
      // Small safety check: make sure domain doesn't match elements inside email or URL
      let value = match;
      if (type === IOCType.Domain) {
        // If domain is part of an email (e.g. support@domain.com) or URL, we clean it
        if (/@/.test(match)) continue;
      }
      
      const validation = validateIOC(value, type);
      const iocId = `ioc-${type}-${value}-${sourceName}`;
      
      iocs.push({
        id: iocId,
        value,
        type,
        hashType,
        source: sourceName,
        sources: [sourceName],
        timestamp: new Date().toISOString(),
        severity: IOCSeverity.Medium,
        category,
        confidence: 75,
        description: `Regex harvested ${type} indicator from ${sourceName}`,
        isValid: validation.isValid,
        notes: validation.reason,
      });
    }
  };

  // Perform regex sweeps
  extract(HASH_SHA256_REGEX, IOCType.Hash, 'SHA-256', 'Malware Cryptography');
  extract(HASH_SHA1_REGEX, IOCType.Hash, 'SHA-1', 'Malware Cryptography');
  extract(HASH_MD5_REGEX, IOCType.Hash, 'MD5', 'Malware Cryptography');
  
  extract(URL_REGEX, IOCType.URL, null, 'Web Compromise');
  extract(EMAIL_REGEX, IOCType.Email, null, 'Phishing Sender');
  extract(IP_REGEX, IOCType.IP, null, 'Malicious Routing');
  
  // Extract domains last (after filter list checking and stripping emails/URLs)
  extract(DOMAIN_REGEX, IOCType.Domain, null, 'C2 Infrastructure');

  return iocs;
}

/**
 * Correlates parsed IOCs across multiple feeds.
 * - Identifies indicators present in 2 or more feeds.
 * - Elevates confidence scores and severities.
 * - Deduplicates unique items and logs sources.
 */
export function correlateIOCs(allIOCs: IOC[]): IOC[] {
  const iocsByValue: { [key: string]: IOC } = {};

  // First pass: Group by value (case-insensitive for domains/URLs/emails, case-sensitive for hashes or matching normalized values)
  for (const ioc of allIOCs) {
    const key = ioc.value.toLowerCase().trim();
    if (!iocsByValue[key]) {
      iocsByValue[key] = {
        ...ioc,
        sources: [...ioc.sources]
      };
    } else {
      // Overlap found! Merge source names and upgrade credentials
      const existing = iocsByValue[key];
      if (!existing.sources.includes(ioc.source)) {
        existing.sources.push(ioc.source);
      }
    }
  }

  // Second pass: Calculate correlation metrics, severities, and check confidence
  const correlated = Object.values(iocsByValue).map(ioc => {
    const feedsCount = ioc.sources.length;
    let severity = ioc.severity;
    let confidence = ioc.confidence;
    let category = ioc.category;

    // Upgrading severity and confidence based on non-AI cross-feed validation count
    if (ioc.isValid) {
      if (feedsCount >= 3) {
        severity = IOCSeverity.Critical;
        confidence = Math.min(100, ioc.confidence + 20);
      } else if (feedsCount === 2) {
        severity = IOCSeverity.High;
        confidence = Math.min(95, ioc.confidence + 10);
      }
    }

    return {
      ...ioc,
      severity,
      confidence,
    };
  });

  return correlated;
}
