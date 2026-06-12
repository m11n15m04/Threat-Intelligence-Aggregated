/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ThreatFeed } from '../types';

export const BUILT_IN_FEEDS: ThreatFeed[] = [
  {
    id: 'abuse-ch-ransomware',
    name: 'Abuse.ch Ransomware Tracker',
    type: 'raw',
    format: 'csv',
    content: `# Abuse.ch Ransomware Tracker IP Feed
# Generated: 2026-06-12 00:00:00 UTC
# Format: ip,status,category,confidence,description
185.220.101.44,active,ransomware,98,Lockbit C2 Node
193.106.191.134,active,malware,95,BlackCat Ransomware Distribution
45.138.16.22,active,c2,90,Cobalt Strike Command & Control
89.248.165.135,active,scanning,75,Mass Threat Scanner activity
109.107.182.20,active,ransomware,95,Conti Affiliate Server
143.244.131.25,active,cryptomining,80,Monero Pool Proxy
192.168.1.105,active,internal_test,30,Private IP testing (Should be flagged as private/invalid)
172.16.10.4,active,lateral_movement,10,Internal IP testing (Should be flagged as private/invalid)
999.888.777.666,active,malware,99,Malformed IP indicator (Should fail validation)`,
    enabled: true,
    lastSync: '2026-06-12T02:00:00Z',
    iocCount: 0,
    isBuiltIn: true,
    category: 'Ransomware & Malware C2',
    description: 'Tracks ransom payload distribution points and command & control (C2) servers on the public web.',
  },
  {
    id: 'phishnet-live',
    name: 'PhishNet Fraud & Phishing Indicators',
    type: 'raw',
    format: 'csv',
    content: `# PhishNet Public Indicator List
# date,indicator,type,category,severity
2026-06-12,http://paypal-verification-secure-alert.com/login,url,phishing,high
2026-06-12,support@accounts-secure-verify.net,email,phishing,medium
2026-06-12,login-update-wellsfargo-banking.net,domain,phishing,high
2026-06-12,193.106.191.134,ip,malware,high
2026-06-12,45.138.16.22,ip,phishing_host,high
2026-06-12,http://malicious-zip-download.info/invoice.pdf.exe,url,malware,high
2026-06-12,invalid_email_test@@domain.com,email,phishing,low`,
    enabled: true,
    lastSync: '2026-06-12T01:45:00Z',
    iocCount: 0,
    isBuiltIn: true,
    category: 'Phishing & Fraud',
    description: 'Tracks active credential harvesting pages, spam origin emails, and phishing redirect domains.',
  },
  {
    id: 'cisa-stix-json',
    name: 'CISA Threat Brief STIX 2.1',
    type: 'raw',
    format: 'stix',
    content: `{
  "type": "bundle",
  "id": "bundle--8f62f854-44e1-45af-aed2-bd77a79a83eb",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--bc33-1",
      "name": "State-Sponsored APT Malware Hash",
      "indicator_types": ["malicious-activity"],
      "pattern": "[file:hashes.'SHA-256' = '85117498c362145e145ef20eefefbc5454555edef999bb333888cfcf11111222']",
      "pattern_type": "stix",
      "valid_from": "2026-06-12T00:00:00Z",
      "description": "BlackCat double-extortion ransomware payload SHA-256 hash"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--bc33-2",
      "name": "APT Backdoor C2 IP Addresses",
      "indicator_types": ["compromised"],
      "pattern": "[ipv4-addr:value = '193.106.191.134']",
      "pattern_type": "stix",
      "valid_from": "2026-06-12T00:00:00Z",
      "description": "Active BlackCat threat host controller"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--bc33-3",
      "name": "Lockbit Payload Delivery Domain",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'lockbit-leaks.su']",
      "pattern_type": "stix",
      "valid_from": "2026-06-12T00:00:00Z",
      "description": "Lockbit secondary blog and leak listing mirror"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--bc33-4",
      "name": "MD5 Hash associated with PDF exploits",
      "indicator_types": ["malicious-activity"],
      "pattern": "[file:hashes.'MD5' = '7de90184c8a2b5e28ff0b118b826de43']",
      "pattern_type": "stix",
      "valid_from": "2026-06-12T00:00:00Z",
      "description": "CVE-2023-26360 PDF exploit document payload hash"
    }
  ]
}`,
    enabled: true,
    lastSync: '2026-06-12T02:10:00Z',
    iocCount: 0,
    isBuiltIn: true,
    category: 'Sovereign Threat Advisories',
    description: 'CISA Joint Cyber Security Advisory structured STIX bundle detailing APT actors and critical infrastructure threats.',
  },
  {
    id: 'alienvault-pulse-txt',
    name: 'AlienVault OTX Pulse #1019',
    type: 'raw',
    format: 'txt',
    content: `# AlienVault OTX Community Pulse #1019
# Target Campaign: Hybrid LockBit/BlackCat Ransomware
# Contains community contributed ransomware and phishing IOCs

# MD5 Hash for exploit PDF
7de90184c8a2b5e28ff0b118b826de43

# Ransomware C2 Server (Strong overlapping node)
193.106.191.134

# Lockbit blog leak site
lockbit-leaks.su

# Active credential harvester domain
login-update-wellsfargo-banking.net

# Valid sovereign domains to verify safe/false-positive filter behavior (should NOT be added as threat block)
google.com

# Known malicious command server IP
185.220.101.44

# Highly active malicious email sender hosting phishing kits
spammer-campaign@tax-refunding.org

# Malicious SHA-1 Hash
a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`,
    enabled: true,
    lastSync: '2026-06-12T02:15:00Z',
    iocCount: 0,
    isBuiltIn: true,
    category: 'Community Threat Intelligence',
    description: 'Crowdsourced community pulse from AlienVault Open Threat Exchange, containing multi-vector threats.',
  }
];
