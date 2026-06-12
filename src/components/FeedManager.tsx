/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Network, Plus, RefreshCw, Layers, Sliders, Check, AlertTriangle, 
  Trash2, Info, FileText, ToggleLeft, ToggleRight, Loader2, ArrowRight
} from 'lucide-react';
import { ThreatFeed } from '../types';

interface FeedManagerProps {
  feeds: ThreatFeed[];
  onToggleFeed: (id: string) => void;
  onAddFeed: (feed: Omit<ThreatFeed, 'iocCount' | 'lastSync'>) => void;
  onRemoveFeed: (id: string) => void;
  onSyncFeed: (id: string) => void;
  onSyncAll: () => void;
}

// Preset Quick Templates for user testing
const TEMPLATES = {
  csv: `# External Rogue Firewall Alert List
# Format: date,indicator,type,category,severity
2026-06-12,203.0.113.88,ip,apt_c2,high
2026-06-12,85.117.44.22,ip,malware_distribution,high
2026-06-12,http://rogue-domain-phishing.org/payload.exe,url,ransomware_payload,high
2026-06-12,malicious-finance-invoice.net,domain,phishing,medium
2026-06-12,spammer-campaign@tax-refunding.org,email,phishing,high`,

  txt: `# Unstructured Web Proxy Log Block (Unstructured Regex test)
Host 10.0.2.15 contacted external C2 server at IP: 185.220.101.44 on port 443.
Security gateway intercepted malicious payload matching MD5 hash d41d8cd98f00b204e9800998ecf8427e.
Proxy flag: User authenticated domain login-update-wellsfargo-banking.net hosting generic malicious phishing hooks.
Please audit email sender: security-alerts-verify@paypal-account-service.net for immediate mailbox mitigation.
File hash SHA-256 discovered on endpoint server: 85117498c362145e145ef20eefefbc5454555edef999bb333888cfcf11111222.`,

  stix: `{
  "type": "bundle",
  "id": "bundle-custom-apt-pulse",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--custom-1",
      "name": "Lockbit secondary blog mirror",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'lockbit-leaks.su']",
      "pattern_type": "stix",
      "description": "Lockbit ransomware secondary blog leak distribution point"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--custom-2",
      "name": "Known active Botnet IP",
      "indicator_types": ["compromised"],
      "pattern": "[ipv4-addr:value = '45.138.16.22']",
      "pattern_type": "stix",
      "description": "Known Cobalt Strike botnet node"
    }
  ]
}`,

  json: `[
  {
    "indicator": "193.106.191.134",
    "category": "ransomware_c2",
    "description": "Known Lockbit loader"
  },
  {
    "indicator": "spammer-campaign@tax-refunding.org",
    "category": "active_phishing_sender",
    "description": "High frequency phishing sender"
  }
]`
};

export default function FeedManager({
  feeds,
  onToggleFeed,
  onAddFeed,
  onRemoveFeed,
  onSyncFeed,
  onSyncAll,
}: FeedManagerProps) {
  const [showAddForm, setShowAddForm] = useState(false);
  const [syncingAll, setSyncingAll] = useState(false);
  const [syncingIndividual, setSyncingIndividual] = useState<string | null>(null);

  // New Feed State
  const [feedName, setFeedName] = useState('');
  const [feedCategory, setFeedCategory] = useState('Cyber Espionage');
  const [feedFormat, setFeedFormat] = useState<'csv' | 'txt' | 'stix' | 'json'>('csv');
  const [feedContent, setFeedContent] = useState('');
  const [feedDescription, setFeedDescription] = useState('');

  // Handle addition
  const submitNewFeed = (e: React.FormEvent) => {
    e.preventDefault();
    if (!feedName.trim()) {
      alert('Please enter a feed name.');
      return;
    }
    if (!feedContent.trim()) {
      alert('Please enter feed text or select a preset template.');
      return;
    }

    onAddFeed({
      id: `custom-feed-${Date.now()}`,
      name: feedName,
      type: 'raw',
      format: feedFormat,
      content: feedContent,
      enabled: true,
      isBuiltIn: false,
      category: feedCategory,
      description: feedDescription || 'Custom security analyst intelligence feed input.'
    });

    // Reset Form
    setFeedName('');
    setFeedCategory('Cyber Espionage');
    setFeedFormat('csv');
    setFeedContent('');
    setFeedDescription('');
    setShowAddForm(false);
  };

  const handleSyncAllClick = () => {
    setSyncingAll(true);
    onSyncAll();
    setTimeout(() => setSyncingAll(false), 900);
  };

  const handleSyncIndividual = (id: string) => {
    setSyncingIndividual(id);
    onSyncFeed(id);
    setTimeout(() => setSyncingIndividual(null), 600);
  };

  const loadTemplate = (type: 'csv' | 'txt' | 'stix' | 'json') => {
    setFeedFormat(type);
    setFeedContent(TEMPLATES[type]);
    if (!feedName) {
      setFeedName(`Custom Intelligence (${type.toUpperCase()})`);
    }
    if (!feedDescription) {
      setFeedDescription(`Custom extracted security indicators in structured ${type.toUpperCase()}`);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-6">
      {/* List of feeds */}
      <div className="lg:col-span-7 bg-[#141415] border border-[#1A1A1C] p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4 pb-4 border-b border-[#1A1A1C]">
          <div>
            <h2 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
              <span className="text-[#00F5FF]">01</span> Intelligence Feeds
            </h2>
            <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
              Active intel repositories currently integrated.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              id="sync-all-button"
              disabled={syncingAll}
              onClick={handleSyncAllClick}
              className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1A1A1C] bg-[#141415] hover:bg-[#1A1A1C] hover:border-slate-600 text-[10px] font-mono font-bold text-slate-200 transition-all cursor-pointer disabled:opacity-50 uppercase tracking-widest"
            >
              {syncingAll ? (
                <Loader2 size={13} className="animate-spin text-[#00F5FF]" />
              ) : (
                <RefreshCw size={13} className="text-[#00F5FF]" />
              )}
              Sync All
            </button>
            <button
              id="show-add-feed-button"
              onClick={() => setShowAddForm(!showAddForm)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#00F5FF] hover:bg-white text-[10px] font-black text-black uppercase tracking-widest transition-all cursor-pointer border border-[#00F5FF]"
            >
              <Plus size={14} />
              Add Feed
            </button>
          </div>
        </div>

        <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
          {feeds.map((feed) => (
            <div
              id={`feed-row-${feed.id}`}
              key={feed.id}
              className={`p-4 border transition-all duration-300 ${
                feed.enabled 
                  ? 'border-[#1A1A1C] bg-[#0A0A0B]' 
                  : 'border-[#1A1A1C]/40 bg-[#0A0A0B]/40 opacity-60'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0 pr-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold font-mono text-[#00F5FF] truncate uppercase">{feed.name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-[#1A1A1C] text-slate-300 font-bold uppercase tracking-widest">
                      {feed.format.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-sans px-2 py-0.5 bg-slate-800 text-white uppercase font-bold tracking-widest">
                      {feed.category}
                    </span>
                    {feed.isBuiltIn && (
                      <span className="text-[9px] font-mono tracking-widest px-1.5 py-0.5 border border-[#1A1A1C] text-slate-400 uppercase font-bold">
                        Built-in
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                    {feed.description}
                  </p>
                </div>
                
                {/* Control switches */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    id={`toggle-feed-${feed.id}`}
                    onClick={() => onToggleFeed(feed.id)}
                    className="p-1 transition-colors"
                  >
                    {feed.enabled ? (
                      <ToggleRight size={24} className="text-[#00F5FF]" />
                    ) : (
                      <ToggleLeft size={24} className="text-slate-500" />
                    )}
                  </button>
                  <button
                    id={`sync-feed-${feed.id}`}
                    disabled={!feed.enabled || syncingIndividual === feed.id}
                    onClick={() => handleSyncIndividual(feed.id)}
                    className="p-1.5 bg-[#1A1A1C] hover:bg-slate-700 text-slate-300 transition-colors disabled:opacity-40"
                  >
                    {syncingIndividual === feed.id ? (
                      <Loader2 size={13} className="animate-spin text-[#00F5FF]" />
                    ) : (
                      <RefreshCw size={13} />
                    )}
                  </button>
                  {!feed.isBuiltIn && (
                    <button
                      id={`delete-feed-${feed.id}`}
                      onClick={() => onRemoveFeed(feed.id)}
                      className="p-1.5 bg-[#1A1A1C] hover:bg-red-950 hover:text-red-400 text-slate-400 transition-colors"
                    >
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              </div>

              {/* Stats and metrics footer */}
              <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 mt-3 pt-3 border-t border-[#1A1A1C] font-mono text-[10px] text-slate-500 uppercase tracking-widest font-bold">
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-none bg-[#00F5FF]" />
                  Parsed Indicators:{' '}
                  <strong className="text-white">{feed.iocCount} IOCs</strong>
                </span>
                <span>
                  Last synchronized:{' '}
                  <strong className="text-white">
                    {feed.lastSync ? new Date(feed.lastSync).toLocaleTimeString() : 'Never'}
                  </strong>
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Add Feed or Templates form */}
      <div className="lg:col-span-5 flex flex-col justify-between bg-[#141415] border border-[#1A1A1C] p-5 h-full">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1C] mb-4">
            <h2 className="text-xl font-black text-white uppercase flex items-center gap-2">
              <span className="text-[#00F5FF]">02</span> Feed Parser
            </h2>
            <div className="flex items-center gap-1 font-mono text-[10px] text-[#00F5FF] uppercase font-bold tracking-widest">
              <span className="w-2 h-2 bg-[#00F5FF] animate-pulse" />
              <span>Interactive</span>
            </div>
          </div>

          <div className="border border-[#1A1A1C] p-3 mb-4">
            <h4 className="font-mono text-[10px] tracking-widest uppercase text-[#00F5FF] font-bold mb-1 flex items-center gap-1">
              <Info size={11} className="text-[#00F5FF]" />
              IOC Parser Quick Start
            </h4>
            <p className="text-slate-400 leading-relaxed text-[10px] font-mono uppercase mb-3">
              The aggregator extracts active IPv4 addresses, domains, URLs, email addresses, and hashes from any format.
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                id="load-template-csv"
                onClick={() => loadTemplate('csv')}
                className="flex items-center justify-between px-2 py-1 bg-[#1A1A1C] hover:text-[#00F5FF] border border-slate-800 text-[10px] font-mono font-bold text-slate-300 text-left transition-all uppercase tracking-widest"
              >
                <span>CSV</span>
                <ArrowRight size={9} />
              </button>
              <button
                id="load-template-txt"
                onClick={() => loadTemplate('txt')}
                className="flex items-center justify-between px-2 py-1 bg-[#1A1A1C] hover:text-[#00F5FF] border border-slate-800 text-[10px] font-mono font-bold text-slate-300 text-left transition-all uppercase tracking-widest"
              >
                <span>TXT</span>
                <ArrowRight size={9} />
              </button>
              <button
                id="load-template-stix"
                onClick={() => loadTemplate('stix')}
                className="flex items-center justify-between px-2 py-1 bg-[#1A1A1C] hover:text-[#00F5FF] border border-slate-800 text-[10px] font-mono font-bold text-slate-300 text-left transition-all uppercase tracking-widest"
              >
                <span>STIX 2.1</span>
                <ArrowRight size={9} />
              </button>
              <button
                id="load-template-json"
                onClick={() => loadTemplate('json')}
                className="flex items-center justify-between px-2 py-1 bg-[#1A1A1C] hover:text-[#00F5FF] border border-slate-800 text-[10px] font-mono font-bold text-slate-300 text-left transition-all uppercase tracking-widest"
              >
                <span>JSON</span>
                <ArrowRight size={9} />
              </button>
            </div>
          </div>

          <form onSubmit={submitNewFeed} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-1 font-bold">Feed Channel Name</label>
              <input
                id="new-feed-name-input"
                type="text"
                placeholder="e.g. Rogue Internal Proxy Logs"
                value={feedName}
                onChange={(e) => setFeedName(e.target.value)}
                className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-[#00F5FF] font-mono uppercase"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-1 font-bold">Category</label>
                <select
                  id="new-feed-category-select"
                  value={feedCategory}
                  onChange={(e) => setFeedCategory(e.target.value)}
                  className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-2 py-2 text-xs text-white focus:outline-none focus:border-[#00F5FF] font-mono uppercase"
                >
                  <option value="Sovereign Threats">Sovereign Threats</option>
                  <option value="Cyber Espionage">Cyber Espionage</option>
                  <option value="Phishing & Fraud">Phishing & Fraud</option>
                  <option value="Ransomware tracker">Ransomware</option>
                  <option value="Malware Infrastructure">Malware Dist.</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-1 font-bold">Format</label>
                <select
                  id="new-feed-format-select"
                  value={feedFormat}
                  onChange={(e) => setFeedFormat(e.target.value as any)}
                  className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-2 py-2 text-xs text-white focus:outline-none focus:border-[#00F5FF] font-mono uppercase text-center"
                >
                  <option value="csv">CSV Focus</option>
                  <option value="txt">TXT Raw</option>
                  <option value="stix">STIX JSON</option>
                  <option value="json">JSON Objects</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest font-bold">Raw Threat Content</label>
                {feedContent && (
                  <span className="text-[9px] font-mono uppercase text-slate-500 font-bold">
                    Chars: {feedContent.length}
                  </span>
                )}
              </div>
              <textarea
                id="new-feed-content-textarea"
                rows={5}
                placeholder="Paste telemetry blocks..."
                value={feedContent}
                onChange={(e) => setFeedContent(e.target.value)}
                className="w-full bg-[#0A0A0B] border border-[#1A1A1C] p-3 text-[10px] text-white placeholder-slate-600 focus:outline-none focus:border-[#00F5FF] font-mono uppercase leading-relaxed"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-[#00F5FF] tracking-widest mb-1 font-bold">Parser Description</label>
              <input
                id="new-feed-description-input"
                type="text"
                placeholder="Description of feed contents"
                value={feedDescription}
                onChange={(e) => setFeedDescription(e.target.value)}
                className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-[#00F5FF] font-mono uppercase"
              />
            </div>

            <button
              id="submit-feed-button"
              type="submit"
              className="w-full flex items-center justify-center gap-1.5 py-3 bg-[#00F5FF] hover:bg-white text-xs font-black text-black transition-all cursor-pointer select-none uppercase tracking-widest mt-2"
            >
              <Check size={14} className="stroke-[3]" />
              Inject & Standardize
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
