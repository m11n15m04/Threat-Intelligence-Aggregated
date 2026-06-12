/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, Radio, Database, Layers, Settings, FileText, 
  Terminal, ShieldCheck, Clock, ExternalLink, RefreshCw 
} from 'lucide-react';

// Import Types
import { ThreatFeed, IOC } from './types';

// Import Utilities & Mock feeds
import { BUILT_IN_FEEDS } from './utils/mockData';
import { parseFeedContent, correlateIOCs } from './utils/parser';

// Import Components
import StatsOverview from './components/StatsOverview';
import FeedManager from './components/FeedManager';
import IOCDatabase from './components/IOCDatabase';
import CorrelationEngine from './components/CorrelationEngine';
import BlocklistGenerator from './components/BlocklistGenerator';
import ThreatSandbox from './components/ThreatSandbox';
import ThreatCharts from './components/ThreatCharts';

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'database' | 'overlaps' | 'blocklist' | 'logs'>('dashboard');
  const [feeds, setFeeds] = useState<ThreatFeed[]>(BUILT_IN_FEEDS);
  const [dismissedIOCs, setDismissedIOCs] = useState<string[]>([]);

  // Compute live synchronized items mapping with manual exclusions applied
  const masterIOCs = useMemo(() => {
    const allParsed: IOC[] = [];
    feeds.forEach(feed => {
      if (feed.enabled) {
        const parsed = parseFeedContent(feed.name, feed.format, feed.content);
        allParsed.push(...parsed);
      }
    });

    const correlated = correlateIOCs(allParsed);

    // Apply manual dismiss state overrides
    return correlated.map(ioc => {
      const isDismissed = dismissedIOCs.includes(ioc.value.toLowerCase());
      if (isDismissed) {
        return {
          ...ioc,
          isValid: false,
          notes: 'Manually dismissed by security analyst.'
        };
      }
      return ioc;
    });
  }, [feeds, dismissedIOCs]);

  // Append Live indicators count per feed tab
  const feedsWithIOCsCount = useMemo(() => {
    return feeds.map(feed => {
      if (!feed.enabled) {
        return { ...feed, iocCount: 0 };
      }
      const parsed = parseFeedContent(feed.name, feed.format, feed.content);
      return {
        ...feed,
        iocCount: parsed.length
      };
    });
  }, [feeds]);

  // Interaction handlers
  const handleToggleFeed = (id: string) => {
    setFeeds(prev => prev.map(feed => {
      if (feed.id === id) {
        return {
          ...feed,
          enabled: !feed.enabled,
          lastSync: new Date().toISOString()
        };
      }
      return feed;
    }));
  };

  const handleAddFeed = (newFeed: Omit<ThreatFeed, 'iocCount' | 'lastSync'>) => {
    setFeeds(prev => [
      ...prev,
      {
        ...newFeed,
        iocCount: 0,
        lastSync: new Date().toISOString()
      }
    ]);
  };

  const handleRemoveFeed = (id: string) => {
    setFeeds(prev => prev.filter(f => f.id !== id));
  };

  const handleSyncFeed = (id: string) => {
    setFeeds(prev => prev.map(f => f.id === id ? { ...f, lastSync: new Date().toISOString() } : f));
  };

  const handleSyncAll = () => {
    setFeeds(prev => prev.map(f => ({ ...f, lastSync: new Date().toISOString() })));
  };

  const handleDismissIOC = (id: string) => {
    const target = masterIOCs.find(i => i.id === id);
    if (target) {
      setDismissedIOCs(prev => [...prev, target.value.toLowerCase()]);
    }
  };

  const handleRestoreIOC = (id: string) => {
    const target = masterIOCs.find(i => i.id === id);
    if (target) {
      setDismissedIOCs(prev => prev.filter(v => v !== target.value.toLowerCase()));
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-slate-100 selection:bg-[#00F5FF] selection:text-black font-sans relative pb-12 border-8 border-[#1A1A1C]">
      {/* Absolute futuristic wire grid lines background */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-25 pointer-events-none" />

      {/* Cyber Ops Header Bar */}
      <header className="border-b border-[#1A1A1C] bg-[#0A0A0B]/80 backdrop-blur-md sticky top-0 z-30 pr-4">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col md:flex-row md:items-end md:justify-between gap-4">
          
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#00F5FF]/10 border border-[#00F5FF]/20 rounded-none">
              <ShieldAlert size={28} className="text-[#00F5FF]" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-3xl font-black tracking-tighter text-white uppercase">
                  Threat Intelligence Aggregator
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#1A1A1C] text-[#00F5FF] border border-[#1A1A1C] uppercase tracking-widest font-bold">
                  v1.2.0-NON-AI
                </span>
              </div>
              <p className="text-sm font-mono text-[#00F5FF] tracking-widest uppercase">
                Technical Documentation & System Requirements
              </p>
            </div>
          </div>

          {/* Operational systems metadata block */}
          <div className="flex flex-col items-end gap-2 text-right">
            <div className="bg-[#00F5FF] text-black px-3 py-1 font-bold text-xs uppercase">
              NON-AI DETERMINISTIC ENGINE
            </div>
            <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-[#00F5FF]">
              <Clock size={12} />
              <span>UTC: 2026-06-12 02:52:00</span>
              <span className="mx-1">|</span>
              <Radio size={12} className="animate-pulse" />
              <span>Status: Active</span>
            </div>
          </div>

        </div>
      </header>

      {/* Primary Dashboard Grid Stage */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-8">
        
        {/* Core telemetry stats panel (Always visible for excellent SOC posture) */}
        <StatsOverview 
          totalFeeds={feeds.length} 
          activeFeeds={feeds.filter(f => f.enabled).length} 
          iocs={masterIOCs} 
        />

        {/* Tab switchers */}
        <div className="flex rounded-none bg-[#1A1A1C] p-1 border border-[#1A1A1C] mb-8 overflow-x-auto text-[10px] uppercase font-mono tracking-widest font-bold">
          <button
            id="tab-dashboard-btn"
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-2 px-4 py-3 transition-colors cursor-pointer ${
              activeTab === 'dashboard' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Radio size={14} />
            Intel Feeds
          </button>
          
          <button
            id="tab-database-btn"
            onClick={() => setActiveTab('database')}
            className={`flex items-center gap-2 px-4 py-3 transition-colors cursor-pointer ${
              activeTab === 'database' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Database size={14} />
            Master Database
          </button>

          <button
            id="tab-overlaps-btn"
            onClick={() => setActiveTab('overlaps')}
            className={`flex items-center gap-2 px-4 py-3 transition-colors cursor-pointer ${
              activeTab === 'overlaps' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Layers size={14} />
            Correlation Overlaps
          </button>

          <button
            id="tab-blocklist-btn"
            onClick={() => setActiveTab('blocklist')}
            className={`flex items-center gap-2 px-4 py-3 transition-colors cursor-pointer ${
              activeTab === 'blocklist' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Settings size={14} />
            Blocklist Compiler
          </button>

          <button
            id="tab-logs-btn"
            onClick={() => setActiveTab('logs')}
            className={`flex items-center gap-2 px-4 py-3 transition-colors cursor-pointer ${
              activeTab === 'logs' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Terminal size={14} />
            Active SIEM
          </button>
        </div>

        {/* Tab view containers with transitions */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.15 }}
          >
            {activeTab === 'dashboard' && (
              <>
                <ThreatCharts iocs={masterIOCs} />
                <FeedManager 
                  feeds={feedsWithIOCsCount} 
                  onToggleFeed={handleToggleFeed}
                  onAddFeed={handleAddFeed}
                  onRemoveFeed={handleRemoveFeed}
                  onSyncFeed={handleSyncFeed}
                  onSyncAll={handleSyncAll}
                />
              </>
            )}

            {activeTab === 'database' && (
              <IOCDatabase 
                iocs={masterIOCs} 
                onDismissIOC={handleDismissIOC}
                onRestoreIOC={handleRestoreIOC}
              />
            )}

            {activeTab === 'overlaps' && (
              <CorrelationEngine iocs={masterIOCs} />
            )}

            {activeTab === 'blocklist' && (
              <BlocklistGenerator iocs={masterIOCs} />
            )}

            {activeTab === 'logs' && (
              <ThreatSandbox iocs={masterIOCs} />
            )}
          </motion.div>
        </AnimatePresence>

        {/* Non-AI design summary card footer */}
        <div className="mt-12 p-6 bg-[#1A1A1C] border border-slate-800 flex flex-col md:flex-row md:items-center md:justify-between gap-4 text-xs font-mono tracking-widest uppercase">
          <div className="flex items-center gap-4">
            <ShieldCheck size={20} className="text-[#00F5FF] shrink-0" />
            <span className="text-slate-400">
              <strong className="text-white">Defensive SOC Best Practice Guardrails Enabled</strong>: All parsing algorithms run locally within browser sandbox container securely. No external telemetry leaks.
            </span>
          </div>
          <div className="flex items-center gap-1 text-[#00F5FF]">
            <span>Powered by regex & hash logic</span>
          </div>
        </div>

      </main>
    </div>
  );
}
