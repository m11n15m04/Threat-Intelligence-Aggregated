/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum IOCType {
  IP = 'IP',
  Domain = 'Domain',
  URL = 'URL',
  Hash = 'Hash',
  Email = 'Email',
}

export enum IOCSeverity {
  Low = 'Low',
  Medium = 'Medium',
  High = 'High',
  Critical = 'Critical',
}

export interface IOC {
  id: string;
  value: string;
  type: IOCType;
  hashType?: 'MD5' | 'SHA-1' | 'SHA-256' | null;
  source: string; // The primary feed name
  sources: string[]; // All feeds that contained this IOC
  timestamp: string; // ISO date
  severity: IOCSeverity;
  category: string; // e.g. "Ransomware", "Botnet", "C2", "Phishing", "Malware", "Cryptomining"
  confidence: number; // 0-100
  description: string;
  isValid: boolean;
  notes?: string;
}

export interface ThreatFeed {
  id: string;
  name: string;
  type: 'url' | 'raw';
  url?: string;
  format: 'json' | 'csv' | 'stix' | 'txt';
  content: string; // Holds raw content or mocked payload
  enabled: boolean;
  lastSync: string | null;
  iocCount: number;
  isBuiltIn: boolean;
  category: string;
  description: string;
}

export interface CorrelationMatch {
  iocValue: string;
  type: IOCType;
  severity: IOCSeverity;
  feeds: string[];
  overlapCount: number;
}

export interface BlocklistConfig {
  type: 'firewall' | 'web_filter' | 'edr';
  format: 'txt' | 'csv' | 'json';
  minSeverity: IOCSeverity;
  minConfidence: number;
  excludedTypes: IOCType[];
}
