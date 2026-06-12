/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useMemo } from 'react';
import { motion } from 'motion/react';
import { 
  FileText, Download, Copy, Settings, Check, Globe, HelpCircle, 
  ShieldAlert, Shield, Layers, FileJson, Table2
} from 'lucide-react';
import { IOC, IOCType, IOCSeverity, BlocklistConfig } from '../types';

interface BlocklistProps {
  iocs: IOC[];
}

export default function BlocklistGenerator({ iocs }: BlocklistProps) {
  const [profile, setProfile] = useState<'firewall' | 'web_filter' | 'edr'>('firewall');
  const [format, setFormat] = useState<'txt' | 'csv' | 'json'>('txt');
  const [minConfidence, setMinConfidence] = useState<number>(75);
  const [minSeverity, setMinSeverity] = useState<'Low' | 'Medium' | 'High' | 'Critical'>('Medium');
  const [includeOnlyCorrelated, setIncludeOnlyCorrelated] = useState<boolean>(false);

  // Check severity order
  const severityRank = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
  };

  // Compile matching IOCs based on parameters
  const targetIOCs = useMemo(() => {
    return iocs.filter(ioc => {
      if (!ioc.isValid) return false;
      
      // Filter by profile compatible indicators
      if (profile === 'firewall' && ioc.type !== IOCType.IP) return false;
      if (profile === 'web_filter' && ioc.type !== IOCType.Domain && ioc.type !== IOCType.URL) return false;
      if (profile === 'edr' && ioc.type !== IOCType.Hash) return false;

      // Filter by confidence threshold
      if (ioc.confidence < minConfidence) return false;

      // Filter by severity
      if (severityRank[ioc.severity] < severityRank[minSeverity]) return false;

      // Filter by correlation state
      if (includeOnlyCorrelated && ioc.sources.length < 2) return false;

      return true;
    });
  }, [iocs, profile, minConfidence, minSeverity, includeOnlyCorrelated]);

  // Compute blocklist string content based on profile and format
  const generatedBlocklist = useMemo(() => {
    if (targetIOCs.length === 0) {
      return `# Threat Intelligence Aggregator - Blocklist Generator\n# Profile: ${profile.toUpperCase()}\n# Parameters: Min Severity: ${minSeverity}, Min Confidence: ${minConfidence}%\n# WARNING: No matching indicators found in local dataset matching thresholds.`;
    }

    const header = `# =========================================================================\n` +
                   `# GENERATED FIREWALL/IPS & SECURITY DEFENSIVE BLOCKLIST\n` +
                   `# Generated On: ${new Date().toISOString()}\n` +
                   `# Target Enforcement Module: ${profile.toUpperCase()}\n` +
                   `# Active Matching Indicators Count: ${targetIOCs.length}\n` +
                   `# Heuristic Configuration: minSeverity=${minSeverity}, minConfidence=${minConfidence}%\n` +
                   `# =========================================================================\n\n`;

    if (profile === 'firewall') {
      if (format === 'txt') {
        const ips = targetIOCs.map(i => i.value).join('\n');
        return header + `# plain simple list of IPv4 addresses\n` + ips;
      }
      if (format === 'csv') {
        let text = '# IPAddress,Severity,Category,Confidence,SourcesCount\n';
        for (const ioc of targetIOCs) {
          text += `"${ioc.value}","${ioc.severity}","${ioc.category}",${ioc.confidence},${ioc.sources.length}\n`;
        }
        return header + text;
      }
      if (format === 'json') {
        return JSON.stringify(targetIOCs.map(i => ({ ip: i.value, severity: i.severity, category: i.category, confidence: i.confidence, sourceFeeds: i.sources })), null, 2);
      }
    }

    if (profile === 'web_filter') {
      if (format === 'txt') {
        // Generates clean dnsmasq host mapping
        const lines = targetIOCs.map(i => {
          if (i.type === IOCType.Domain) {
            return `address=/${i.value}/0.0.0.0`;
          } else {
            return `# URL blocker: ${i.value}`;
          }
        }).join('\n');
        return header + `# DNS Sinkhole / RPZ Map (AdBlock / dnsmasq schema)\n` + lines;
      }
      if (format === 'csv') {
        let text = '# IndicatorValue,Type,Severity,Category,Confidence\n';
        for (const ioc of targetIOCs) {
          text += `"${ioc.value}","${ioc.type}","${ioc.severity}","${ioc.category}",${ioc.confidence}\n`;
        }
        return header + text;
      }
      if (format === 'json') {
        return JSON.stringify(targetIOCs.map(i => ({ WebIndicator: i.value, type: i.type, severity: i.severity, confidence: i.confidence })), null, 2);
      }
    }

    if (profile === 'edr') {
      if (format === 'txt') {
        const hashes = targetIOCs.map(i => i.value).join('\n');
        return header + `# Plain MD5 & SHA-256 signatures for Carbon Black / Falcon endpoint blockers\n` + hashes;
      }
      if (format === 'csv') {
        let text = '# FileHash,HashType,EnforcementAction,Severity,Category\n';
        for (const ioc of targetIOCs) {
          const typeLabel = ioc.hashType || 'MD5/SHA256';
          text += `"${ioc.value}","${typeLabel}","BLOCK","${ioc.severity}","${ioc.category}"\n`;
        }
        return header + text;
      }
      if (format === 'json') {
        return JSON.stringify(targetIOCs.map(i => ({ FileHash: i.value, hashType: i.hashType || 'unknown', behavior: 'BLOCK', category: i.category, severity: i.severity })), null, 2);
      }
    }

    return '';
  }, [targetIOCs, profile, format, minConfidence, minSeverity]);

  // Handle triggering download
  const handleDownload = () => {
    let extension = format;
    let mime = 'text/plain';
    if (format === 'json') mime = 'application/json';
    if (format === 'csv') mime = 'text/csv';

    const blob = new Blob([generatedBlocklist], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threat_agg_blocklist_${profile}_${minSeverity.toLowerCase()}.${extension}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyClipboard = () => {
    navigator.clipboard.writeText(generatedBlocklist);
    alert('Blocklist copied to clipboard successfully!');
  };

  return (
    <div id="blocklist-generator-panel" className="bg-[#141415] border border-[#1A1A1C] p-5 mb-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-[#1A1A1C]">
        <div>
          <h2 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-[#00F5FF]">05</span> Security Blocklist Compiler
          </h2>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Instantly render, filter, and compile actionable feeds.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Tuning Configuration box */}
        <div className="lg:col-span-4 bg-[#0A0A0B] p-4 border border-[#1A1A1C] space-y-4">
          <h3 className="text-[10px] font-mono uppercase tracking-widest text-[#00F5FF] font-bold mb-3 flex items-center gap-1">
            <Settings size={12} className="text-[#00F5FF]" />
            Blocklist Parameters
          </h3>

          {/* Profile Choice */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-2 font-bold">Target Enforcement Agent</label>
            <div className="grid grid-cols-3 gap-1 bg-[#1A1A1C] p-1 border border-[#1A1A1C] text-[10px] font-mono font-bold tracking-widest uppercase">
              <button
                id="profile-firewall-btn"
                onClick={() => { setProfile('firewall'); }}
                className={`py-2 text-center transition-all cursor-pointer ${
                  profile === 'firewall' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                Firewalls
              </button>
              <button
                id="profile-webfilter-btn"
                onClick={() => { setProfile('web_filter'); }}
                className={`py-2 text-center transition-all cursor-pointer ${
                  profile === 'web_filter' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                Web Filters
              </button>
              <button
                id="profile-edr-btn"
                onClick={() => { setProfile('edr'); }}
                className={`py-2 text-center transition-all cursor-pointer ${
                  profile === 'edr' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                EDR / AV
              </button>
            </div>
          </div>

          {/* Export Schema */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-2 font-bold">Output File Format</label>
            <div className="grid grid-cols-3 gap-1 bg-[#1A1A1C] p-1 border border-[#1A1A1C] text-[10px] font-mono font-bold tracking-widest uppercase">
              <button
                id="format-txt-btn"
                onClick={() => setFormat('txt')}
                className={`py-2 text-center transition-all cursor-pointer ${
                  format === 'txt' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                TXT List
              </button>
              <button
                id="format-csv-btn"
                onClick={() => setFormat('csv')}
                className={`py-2 text-center transition-all cursor-pointer ${
                  format === 'csv' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                CSV Table
              </button>
              <button
                id="format-json-btn"
                onClick={() => setFormat('json')}
                className={`py-2 text-center transition-all cursor-pointer ${
                  format === 'json' ? 'bg-white text-black' : 'text-slate-400 hover:text-white'
                }`}
              >
                JSON Array
              </button>
            </div>
          </div>

          {/* Filters selection */}
          <div className="space-y-4 pt-4 border-t border-[#1A1A1C]">
            <div>
              <div className="flex justify-between text-[10px] font-mono uppercase tracking-widest text-[#00F5FF] mb-1 font-bold">
                <span>Min Intel Confidence</span>
                <span className="text-white">{minConfidence}%</span>
              </div>
              <input
                id="confidence-range-slider"
                type="range"
                min="30"
                max="95"
                step="5"
                value={minConfidence}
                onChange={(e) => setMinConfidence(parseInt(e.target.value, 10))}
                className="w-full h-1 bg-slate-800 appearance-none cursor-pointer accent-[#00F5FF]"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-2 font-bold">Min Threat Severity</label>
              <select
                id="blocklist-min-severity"
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value as any)}
                className="w-full bg-[#1A1A1C] border border-[#1A1A1C] px-2 py-2 text-[10px] text-white focus:outline-none focus:border-[#00F5FF] font-mono uppercase tracking-widest font-bold"
              >
                <option value="Low">Low (All)</option>
                <option value="Medium">Medium & above</option>
                <option value="High">High & Critical</option>
                <option value="Critical">Critical only</option>
              </select>
            </div>

            <div className="flex items-center gap-2 pt-1">
              <input
                id="correlated-checkbox"
                type="checkbox"
                checked={includeOnlyCorrelated}
                onChange={(e) => setIncludeOnlyCorrelated(e.target.checked)}
                className="w-4 h-4 text-[#00F5FF] bg-[#1A1A1C] border-[#1A1A1C] focus:ring-0 cursor-pointer rounded-none"
              />
              <label htmlFor="correlated-checkbox" className="text-[10px] uppercase font-bold tracking-widest font-mono text-white cursor-pointer leading-tight select-none mt-1">
                Limit to Correlated Only
              </label>
            </div>
          </div>
        </div>

        {/* Action Preview and Export Code Panel */}
        <div className="lg:col-span-8 flex flex-col justify-between border border-[#1A1A1C] p-4 bg-[#0A0A0B] text-xs">
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1C] mb-4 text-[10px] uppercase font-bold tracking-widest">
              <span className="font-mono text-[#00F5FF] flex items-center gap-2">
                <FileText size={14} className="text-[#00F5FF]" />
                Live Preview ({targetIOCs.length} indicators)
              </span>
              <div className="flex items-center gap-2">
                <button
                  id="copy-blocklist-btn"
                  onClick={handleCopyClipboard}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1A1A1C] hover:bg-slate-800 text-white font-mono transition-all cursor-pointer"
                >
                  <Copy size={12} />
                  Copy List
                </button>
                <button
                  id="download-blocklist-btn"
                  onClick={handleDownload}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#00F5FF] hover:bg-white text-black font-black font-mono transition-all cursor-pointer"
                >
                  <Download size={12} className="stroke-[3]" />
                  Download
                </button>
              </div>
            </div>

            {/* Simulated file window */}
            <div className="bg-[#1A1A1C] border border-[#141415] p-4 flex-grow overflow-y-auto">
              <pre className="font-mono text-[10px] text-[#00F5FF] whitespace-pre-wrap leading-relaxed tracking-wider">
                {generatedBlocklist}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
