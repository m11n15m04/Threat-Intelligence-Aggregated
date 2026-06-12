/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { motion } from 'motion/react';
import { 
  Terminal, Play, Trash2, ShieldAlert, Sparkles, AlertTriangle, 
  CheckCircle2, HelpCircle, FileText, Globe, Clipboard, ArrowRight
} from 'lucide-react';
import { IOC, IOCType, IOCSeverity } from '../types';
import { parseTextRegex } from '../utils/parser';

interface SandboxProps {
  iocs: IOC[];
}

interface LogAlert {
  lineNum: number;
  rawLine: string;
  matchedIndicator: string;
  type: IOCType;
  severity: IOCSeverity;
  category: string;
  sources: string[];
  description: string;
}

const LOG_PRESETS = {
  firewall: `Jun 12 02:40:11 edge-firewall-01 src=10.0.12.19 dst=193.106.191.134 proto=TCP sport=49112 dport=443 action=ALLOW bytes=3420
Jun 12 02:40:15 edge-firewall-01 src=10.0.12.19 dst=8.8.8.8 proto=UDP sport=53 dport=53 action=ALLOW bytes=112
Jun 12 02:40:55 edge-firewall-01 src=10.20.1.44 dst=192.168.1.105 proto=TCP sport=49202 dport=22 action=ALLOW bytes=840 (Internal activity)
Jun 12 02:41:02 edge-firewall-01 src=10.0.12.19 dst=185.220.101.44 proto=TCP sport=49155 dport=8080 action=DENY bytes=0`,

  proxy: `10.0.8.22 - - [12/Jun/2026:02:41:19 +0000] "GET http://paypal-verification-secure-alert.com/login HTTP/1.1" 200 4502 "http://google.com/" "Mozilla/5.0"
10.0.8.22 - - [12/Jun/2026:02:42:01 +0000] "GET /index.php HTTP/1.1" 200 12053 "https://wikipedia.org/" "Mozilla/5.0"
10.0.8.31 - - [12/Jun/2026:02:43:35 +0000] "GET /api/v2/telemetry HTTP/1.1" 200 340 "login-update-wellsfargo-banking.net" "Go-http-client/1.1"
10.0.8.35 - - [12/Jun/2026:02:43:55 +0000] "POST http://malicious-zip-download.info/invoice.pdf.exe HTTP/1.1" 301 240 "https://accounts.verify.com/" "Mozilla/5.0"`,

  endpoint: `Process C:\\Windows\\System32\\cmd.exe started by user Administrator.
Endpoint Security alert - MD5 Hash matched on process launch: 7de90184c8a2b5e28ff0b118b826de43. SHA-256 equivalent payload is clean.
Process initiated external callback connection to lockbit-leaks.su over port 443.
System process svchost.exe queried benign records on google.com (MITIGATED by whitelist).`
};

export default function ThreatSandbox({ iocs }: SandboxProps) {
  const [logContent, setLogContent] = useState('');
  const [alerts, setAlerts] = useState<LogAlert[]>([]);
  const [hasScanned, setHasScanned] = useState(false);

  // Run correlation scan
  const handleScanLogs = () => {
    if (!logContent.trim()) {
      alert('Please enter or load mock log data to scan.');
      return;
    }

    const lines = logContent.split('\n');
    const detectedAlerts: LogAlert[] = [];

    lines.forEach((line, index) => {
      if (!line.trim()) return;

      // Extract raw indicators inside this specific line
      const lineIOCs = parseTextRegex(line, 'Sandbox Log Scanner');

      // Check if any of these matching indicators are registered inside our active IOC Database
      for (const extracted of lineIOCs) {
        // Find if we have a match in the active threat list (must be marked as valid to trigger cyber alert)
        const match = iocs.find(i => i.isValid && i.value.toLowerCase() === extracted.value.toLowerCase());

        if (match) {
          detectedAlerts.push({
            lineNum: index + 1,
            rawLine: line,
            matchedIndicator: match.value,
            type: match.type,
            severity: match.severity,
            category: match.category,
            sources: match.sources,
            description: match.description
          });
        }
      }
    });

    setAlerts(detectedAlerts);
    setHasScanned(true);
  };

  const loadPreset = (presetKey: 'firewall' | 'proxy' | 'endpoint') => {
    setLogContent(LOG_PRESETS[presetKey]);
    setAlerts([]);
    setHasScanned(false);
  };

  const clearSandbox = () => {
    setLogContent('');
    setAlerts([]);
    setHasScanned(false);
  };

  return (
    <div id="threat-sandbox-panel" className="bg-[#141415] border border-[#1A1A1C] p-5 mb-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-[#1A1A1C]">
        <div>
          <h2 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-emerald-400">06</span> SOC Log Simulator
          </h2>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Simulate a SIEM pipeline. Parse production firewalls, proxies, and endpoint logs.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Play Space and Input */}
        <div className="lg:col-span-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h3 className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 font-bold flex items-center gap-1">
              <FileText size={12} className="text-emerald-400" />
              Raw Console Input
            </h3>
            
            {/* Template Presets */}
            <div className="flex items-center gap-1.5 text-[10px] font-mono tracking-widest font-bold uppercase">
              <span className="text-slate-500 mr-1">Load:</span>
              <button
                id="preset-firewall-btn"
                onClick={() => loadPreset('firewall')}
                className="px-2 py-1 bg-[#1A1A1C] hover:bg-white hover:text-black text-slate-300 transition-all cursor-pointer"
              >
                Firewall
              </button>
              <button
                id="preset-proxy-btn"
                onClick={() => loadPreset('proxy')}
                className="px-2 py-1 bg-[#1A1A1C] hover:bg-white hover:text-black text-slate-300 transition-all cursor-pointer"
              >
                Proxy
              </button>
              <button
                id="preset-endpoint-btn"
                onClick={() => loadPreset('endpoint')}
                className="px-2 py-1 bg-[#1A1A1C] hover:bg-white hover:text-black text-slate-300 transition-all cursor-pointer"
              >
                Host
              </button>
            </div>
          </div>

          <div className="relative">
            <textarea
              id="sandbox-log-textarea"
              rows={9}
              placeholder="PASTE RAW LOG ENTRIES HERE..."
              className="w-full bg-[#0A0A0B] border border-[#1A1A1C] p-4 text-[10px] text-emerald-400 placeholder-slate-700 focus:outline-none focus:border-emerald-500 font-mono leading-relaxed uppercase font-bold tracking-widest resize-none"
              value={logContent}
              onChange={(e) => {
                setLogContent(e.target.value);
                setHasScanned(false);
              }}
            />
            {logContent && (
              <button
                id="clear-sandbox-btn"
                onClick={clearSandbox}
                className="absolute right-3.5 bottom-3.5 px-3 py-1.5 bg-[#1A1A1C] text-white hover:bg-slate-800 transition-colors text-[10px] uppercase tracking-widest font-black font-mono flex items-center gap-1.5"
              >
                <Trash2 size={12} />
                Reset
              </button>
            )}
          </div>

          <button
            id="scan-sandbox-logs-btn"
            onClick={handleScanLogs}
            className="w-full flex items-center justify-center gap-2 py-3 bg-emerald-400 hover:bg-emerald-300 text-black text-[10px] font-black uppercase tracking-widest transition-all cursor-pointer"
          >
            <Play size={14} className="fill-black stroke-none" />
            Execute Analysis Scan
          </button>
        </div>

        {/* Alerts and Telemetry Output Screen */}
        <div className="lg:col-span-6 border-l border-[#1A1A1C] pl-6 ml-2 bg-[#0A0A0B] flex flex-col justify-between py-2">
          <div>
            <h3 className="text-[10px] font-mono uppercase tracking-widest text-[#00F5FF] font-black mb-4 pb-3 border-b border-[#1A1A1C] flex items-center gap-2">
              <Terminal size={14} className="text-[#00F5FF]" />
              Threat Indicator Alerts
            </h3>

            {!hasScanned ? (
              <div className="py-12 text-center text-slate-500 font-mono text-[10px] uppercase tracking-widest font-bold">
                Awaiting input logs...
              </div>
            ) : alerts.length === 0 ? (
              <div className="py-12 text-center text-slate-400 font-mono text-[10px] uppercase tracking-widest font-bold flex flex-col items-center justify-center gap-3">
                <CheckCircle2 size={32} className="text-emerald-500" />
                <span>CLEAN: 0 Active Threats Identified. No registered matches.</span>
              </div>
            ) : (
              <div className="space-y-4 max-h-[290px] overflow-y-auto pr-2">
                {alerts.map((alert, index) => (
                  <div
                    id={`sandbox-alert-item-${index}`}
                    key={index}
                    className="p-4 bg-[#141415] border-l-4 border-red-500 font-mono border-t border-b border-r border-[#1A1A1C]"
                  >
                    <div className="flex items-start justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-1.5 text-[10px] text-red-400 font-black tracking-widest uppercase">
                        <ShieldAlert size={14} />
                        <span>THREAT DETECTED (LN {alert.lineNum})</span>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 bg-red-900/30 text-red-400 font-black uppercase tracking-widest">
                        {alert.severity}
                      </span>
                    </div>

                    <div className="mt-3 text-[10px] uppercase font-bold tracking-widest">
                      <span className="text-slate-500">Match Alert:</span>{' '}
                      <strong className="text-white select-all bg-red-900/30 px-1 py-0.5 ml-1">{alert.matchedIndicator}</strong>
                    </div>

                    <div className="text-[10px] text-slate-400 mt-2 leading-relaxed bg-[#0A0A0B] p-3 border border-[#1A1A1C] uppercase tracking-wider font-bold">
                      <span className="text-red-400 font-black">LOG:</span> "{alert.rawLine.trim()}"
                    </div>

                    {/* Threat Provenance */}
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-[10px] mt-3 text-slate-500 pt-3 border-t border-[#1A1A1C] uppercase font-bold tracking-widest">
                      <span>Cat: <strong className="text-white ml-0.5">{alert.category}</strong></span>
                      <span className="flex items-center gap-1.5">
                        In:
                        {alert.sources.map(src => (
                          <span key={src} className="px-1.5 bg-[#1A1A1C] text-white">
                            {src}
                          </span>
                        ))}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {hasScanned && alerts.length > 0 && (
            <div className="p-4 bg-red-900/20 shadow-[0_0_15px_rgba(239,68,68,0.1)] text-[10px] font-black tracking-widest font-mono text-center text-red-500 mt-4 uppercase border border-red-900/50">
              ⚠️ Discovered {alerts.length} threats. Compile blocklist immediately.
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
