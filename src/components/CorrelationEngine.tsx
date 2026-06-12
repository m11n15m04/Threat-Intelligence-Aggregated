/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Layers, AlertOctagon, HelpCircle, ArrowRight, ShieldAlert, Check, Network, Sparkles } from 'lucide-react';
import { IOC, IOCType, IOCSeverity } from '../types';

interface CorrelationEngineProps {
  iocs: IOC[];
}

export default function CorrelationEngine({ iocs }: CorrelationEngineProps) {
  const [selectedOverlapId, setSelectedOverlapId] = useState<string | null>(null);

  // Extract all threat indicators flagged in 2 or more feeds
  const overlaps = iocs.filter(ioc => ioc.isValid && ioc.sources.length >= 2);

  const selectedOverlap = overlaps.find(o => o.id === selectedOverlapId) || overlaps[0];

  return (
    <div id="correlation-engine-panel" className="bg-[#141415] border border-[#1A1A1C] p-5 mb-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-[#1A1A1C]">
        <div>
          <h2 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-[#00F5FF]">04</span> Core Correlation Engine
          </h2>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Standardized heuristic scoring scans all loaded feeds to locate identical indicators. Repeated entities are elevated automatically.
          </p>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono tracking-widest uppercase font-bold">
          <span className="text-[#00F5FF] bg-[#1A1A1C] px-3 py-1 border border-[#1A1A1C]">
            {overlaps.length} Overlapping Clusters
          </span>
        </div>
      </div>

      {overlaps.length === 0 ? (
        <div className="py-12 text-center text-slate-500 font-mono text-[10px] uppercase font-bold tracking-widest">
          No correlation indicators parsed. Load multiple custom feeds with overlapping IPs, domains, or hashes.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Overlapping Listings column */}
          <div className="lg:col-span-4 space-y-3 max-h-[380px] overflow-y-auto pr-1">
            <h3 className="text-[10px] font-mono uppercase tracking-widest text-[#00F5FF] font-bold mb-3 pl-1">
              Suspicious Entities ({overlaps.length})
            </h3>
            {overlaps.map(ioc => {
              const matchesSelected = selectedOverlap && selectedOverlap.id === ioc.id;
              return (
                <button
                  id={`overlap-cluster-item-${ioc.id}`}
                  key={ioc.id}
                  onClick={() => setSelectedOverlapId(ioc.id)}
                  className={`w-full text-left p-3.5 border transition-all duration-200 cursor-pointer ${
                    matchesSelected
                      ? 'border-[#00F5FF] bg-white shadow-[0_0_15px_rgba(0,245,255,0.2)] text-black'
                      : 'border-[#1A1A1C] bg-[#0A0A0B] hover:bg-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <span className={`text-[10px] font-mono truncate max-w-[200px] select-all font-bold ${matchesSelected ? "text-black" : "text-white"}`}>
                      {ioc.value}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 font-black uppercase ${matchesSelected ? "bg-[#00F5FF] text-black" : "bg-red-900/30 text-red-400"}`}>
                      {ioc.severity}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] mt-2 tracking-widest uppercase font-bold">
                    <span className={`font-sans px-1.5 py-0.5 ${matchesSelected ? 'bg-black text-[#00F5FF]' : 'bg-[#1A1A1C] text-[#00F5FF]'}`}>
                      {ioc.type}
                    </span>
                    <span className={`font-mono flex items-center gap-1 ${matchesSelected ? 'text-black' : 'text-red-400'}`}>
                      <Network size={10} />
                      {ioc.sources.length} Overlapping
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Interactive Flow Visualizer column */}
          {selectedOverlap && (
            <div className="lg:col-span-8 flex flex-col justify-between border-l border-[#1A1A1C] pl-6 ml-2 bg-[#0A0A0B] min-h-[360px] relative p-6">
              <div>
                <div className="flex items-start justify-between pb-3 border-b border-[#1A1A1C] mb-6 font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest font-black block">Selected Overlap Entity</span>
                    <h3 className="text-sm text-white font-black break-all select-all mt-1 uppercase">{selectedOverlap.value}</h3>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest font-black block">Risk Level</span>
                    <span className="text-[10px] font-bold text-black bg-[#00F5FF] px-2 py-0.5 uppercase mt-1 inline-block">
                      Critical Score: {selectedOverlap.confidence}%
                    </span>
                  </div>
                </div>

                {/* Cyber Security Hub Node Diagram */}
                <div className="p-4 bg-[#141415] border border-[#1A1A1C] flex flex-col items-center justify-center relative overflow-hidden mb-6 min-h-[180px]">
                  {/* SVG Nodes Connecter */}
                  <div className="relative w-full max-w-sm flex flex-col items-center justify-center py-4">
                    
                    {/* The Target Node */}
                    <div className="relative z-10 p-4 bg-[#00F5FF] text-black font-mono shadow-[0_0_20px_rgba(0,245,255,0.2)] mb-10 w-full text-center">
                      <ShieldAlert size={18} className="mx-auto mb-2 text-black" />
                      <strong className="text-sm tracking-widest uppercase font-black">Correlated Vector</strong>
                      <p className="text-[10px] font-bold mt-1 truncate">{selectedOverlap.value}</p>
                    </div>

                    {/* Source feeder nodes in grid */}
                    <div className="w-full grid grid-cols-2 gap-4 relative z-10">
                      {selectedOverlap.sources.map((src, index) => (
                        <div key={src} className="flex flex-col items-center relative">
                          <div className="absolute -top-7 left-1/2 w-0.5 h-7 bg-[#1A1A1C] -translate-x-1/2" />
                          <div className="p-3 bg-[#0A0A0B] border border-[#1A1A1C] text-center text-white text-[10px] font-bold font-mono tracking-widest uppercase shadow w-full truncate select-all">
                            {src}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="bg-[#141415] p-4 border-l-4 border-[#00F5FF] font-mono text-[10px] uppercase font-bold tracking-widest">
                  <h4 className="text-[10px] text-slate-500 mb-2 flex items-center gap-1">
                    <Sparkles size={11} className="text-[#00F5FF]" />
                    Auto-Heuristic Applied
                  </h4>
                  <ul className="space-y-2 text-slate-300">
                    <li>• Found in <strong className="text-[#00F5FF]">{selectedOverlap.sources.length} feeds</strong>. +20 confidence.</li>
                    <li>• Escalated to <strong className="text-white bg-red-900/30 px-1">{selectedOverlap.severity}</strong>.</li>
                    <li>• Score: <span className="text-white">{selectedOverlap.confidence}% high probability</span>.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
