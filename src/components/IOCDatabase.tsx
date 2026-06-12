/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Database, Search, Filter, ShieldAlert, Globe, Link2, 
  Mail, Hash as HashIcon, Trash, CheckCircle, AlertTriangle, 
  HelpCircle, ChevronDown, ChevronUp, Download, Copy, RefreshCw, XCircle
} from 'lucide-react';
import { IOC, IOCType, IOCSeverity } from '../types';

interface IOCDatabaseProps {
  iocs: IOC[];
  onDismissIOC: (id: string) => void;
  onRestoreIOC: (id: string) => void;
}

export default function IOCDatabase({ iocs, onDismissIOC, onRestoreIOC }: IOCDatabaseProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [validityFilter, setValidityFilter] = useState<'ALL' | 'VALID' | 'INVALID'>('VALID');
  const [expandedIOCId, setExpandedIOCId] = useState<string | null>(null);

  // Filter master dataset
  const filteredIOCs = useMemo(() => {
    return iocs.filter(ioc => {
      // Search
      const matchesSearch = 
        ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ioc.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ioc.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ioc.description.toLowerCase().includes(searchTerm.toLowerCase());
        
      // Type
      const matchesType = selectedType === 'ALL' || ioc.type === selectedType;
      
      // Severity
      const matchesSeverity = selectedSeverity === 'ALL' || ioc.severity === selectedSeverity;
      
      // Validity
      const matchesValidity = 
        validityFilter === 'ALL' ||
        (validityFilter === 'VALID' && ioc.isValid) ||
        (validityFilter === 'INVALID' && !ioc.isValid);

      return matchesSearch && matchesType && matchesSeverity && matchesValidity;
    });
  }, [iocs, searchTerm, selectedType, selectedSeverity, validityFilter]);

  // Copy helper
  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    alert(`Copied indicator to clipboard: ${val}`);
  };

  // Get indicator icon
  const getIOCIcon = (type: IOCType) => {
    switch (type) {
      case IOCType.IP: return <Globe size={14} className="text-sky-400" />;
      case IOCType.Domain: return <Database size={14} className="text-teal-400" />;
      case IOCType.URL: return <Link2 size={14} className="text-violet-400" />;
      case IOCType.Hash: return <HashIcon size={14} className="text-amber-400" />;
      case IOCType.Email: return <Mail size={14} className="text-rose-400" />;
    }
  };

  // Get severity styles
  const getSeverityBadge = (severity: IOCSeverity, isValid: boolean) => {
    if (!isValid) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
          Scrubbed
        </span>
      );
    }
    switch (severity) {
      case IOCSeverity.Critical:
        return (
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-950 border border-red-500/30 text-red-400 uppercase tracking-wide">
            Critical
          </span>
        );
      case IOCSeverity.High:
        return (
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-950 border border-amber-500/30 text-amber-400 uppercase tracking-wide">
            High
          </span>
        );
      case IOCSeverity.Medium:
        return (
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-yellow-950 border border-yellow-500/30 text-yellow-400 uppercase tracking-wide">
            Medium
          </span>
        );
      case IOCSeverity.Low:
        return (
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-850 border border-slate-750 text-slate-400 uppercase tracking-wide">
            Low
          </span>
        );
    }
  };

  return (
    <div id="ioc-database-panel" className="bg-[#141415] border border-[#1A1A1C] p-5 mb-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-[#1A1A1C]">
        <div>
          <h2 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-[#00F5FF]">03</span> Normalized Master Database
          </h2>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Browse and query standardized cybersecurity indicators.
          </p>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono tracking-widest uppercase font-bold">
          <span className="text-slate-500">Matches:</span>
          <span className="text-black bg-[#00F5FF] px-3 py-1 font-black shadow-[0_0_10px_rgba(0,245,255,0.2)]">
            {filteredIOCs.length}
          </span>
        </div>
      </div>

      {/* Database Filters & Query Tools */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3 mb-6">
        <div className="md:col-span-4 relative">
          <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-slate-500">
            <Search size={14} />
          </span>
          <input
            id="ioc-search-input"
            type="text"
            placeholder="Search indicator, source..."
            className="w-full bg-[#0A0A0B] border border-[#1A1A1C] pl-9 pr-3 py-2 text-[10px] text-white placeholder-slate-600 focus:outline-none focus:border-[#00F5FF] font-mono uppercase tracking-widest"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* Indicator Types dropdown */}
        <div className="md:col-span-2">
          <select
            id="ioc-type-filter"
            className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-2.5 py-2 text-[10px] text-white focus:outline-none focus:border-[#00F5FF] font-mono uppercase tracking-widest"
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
          >
            <option value="ALL">All Types</option>
            <option value="IP">IPs</option>
            <option value="Domain">Domains</option>
            <option value="URL">URLs</option>
            <option value="Hash">Hashes</option>
            <option value="Email">Emails</option>
          </select>
        </div>

        {/* Severity filter dropdown */}
        <div className="md:col-span-2">
          <select
            id="ioc-severity-filter"
            className="w-full bg-[#0A0A0B] border border-[#1A1A1C] px-2.5 py-2 text-[10px] text-white focus:outline-none focus:border-[#00F5FF] font-mono uppercase tracking-widest"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="ALL">All Sev</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        {/* Validity options */}
        <div className="md:col-span-4 flex border border-[#1A1A1C] overflow-hidden w-full bg-[#0A0A0B] p-0.5 text-[10px] font-mono uppercase tracking-widest font-bold">
          <button
            id="filter-valid-iocs"
            onClick={() => setValidityFilter('VALID')}
            className={`flex-1 py-1.5 px-2 text-center transition-all cursor-pointer ${
              validityFilter === 'VALID' 
                ? 'bg-white text-black' 
                : 'text-slate-500 hover:text-white'
            }`}
          >
            Valid
          </button>
          <button
            id="filter-invalid-iocs"
            onClick={() => setValidityFilter('INVALID')}
            className={`flex-1 py-1.5 px-2 text-center transition-all cursor-pointer ${
              validityFilter === 'INVALID' 
                ? 'bg-[#00F5FF] text-black' 
                : 'text-slate-500 hover:text-white'
            }`}
          >
            Scrubbed
          </button>
          <button
            id="filter-all-iocs"
            onClick={() => setValidityFilter('ALL')}
            className={`flex-1 py-1.5 px-2 text-center transition-all cursor-pointer ${
              validityFilter === 'ALL' 
                ? 'bg-[#1A1A1C] text-white' 
                : 'text-slate-500 hover:text-white'
            }`}
          >
            All
          </button>
        </div>
      </div>

      {/* Main Database Table Grid */}
      <div className="overflow-x-auto border border-[#1A1A1C] max-h-[500px] overflow-y-auto">
        <table className="w-full text-left text-[10px] font-mono uppercase tracking-wider">
          <thead>
            <tr className="bg-[#0A0A0B] border-b border-[#1A1A1C] text-slate-500 sticky top-0 z-10">
              <th className="py-4 px-4 font-bold tracking-widest">Indicator Value</th>
              <th className="py-4 px-2 font-bold tracking-widest">Type</th>
              <th className="py-4 px-2 font-bold tracking-widest">Category</th>
              <th className="py-4 px-2 font-bold tracking-widest">Severity</th>
              <th className="py-4 px-2 font-bold tracking-widest text-center">Confidence</th>
              <th className="py-4 px-2 font-bold tracking-widest">Sources</th>
              <th className="py-4 px-4 font-bold tracking-widest text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1A1A1C]">
            {filteredIOCs.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                  No threat indicators matching selected criteria.
                </td>
              </tr>
            ) : (
              filteredIOCs.map((ioc) => {
                const isExpanded = expandedIOCId === ioc.id;
                return (
                  <>
                    <tr
                      id={`ioc-row-${ioc.id}`}
                      key={ioc.id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        !ioc.isValid ? 'bg-slate-950/20 text-slate-500' : 'text-slate-200'
                      }`}
                    >
                      {/* Indicator text value */}
                      <td className="py-3.5 px-4 font-mono select-all truncate max-w-[280px]" title={ioc.value}>
                        <div className="flex items-center gap-2">
                          <button
                            id={`expand-row-btn-${ioc.id}`}
                            onClick={() => setExpandedIOCId(isExpanded ? null : ioc.id)}
                            className="p-0.5 hover:bg-slate-800 rounded text-slate-500 hover:text-slate-300"
                          >
                            {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                          </button>
                          <span>{ioc.value}</span>
                        </div>
                      </td>

                      {/* Indicator Type mapping */}
                      <td className="py-3.5 px-2 font-mono">
                        <div className="flex items-center gap-1.5">
                          {getIOCIcon(ioc.type)}
                          <span className="text-[10px] tracking-wider">{ioc.type}</span>
                        </div>
                      </td>

                      {/* Normalized Threat Category */}
                      <td className="py-3.5 px-2">
                        <span className="text-slate-300 font-mono text-[11px] font-semibold bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded shadow-sm">
                          {ioc.category}
                        </span>
                      </td>

                      {/* Normalized Severity Rating */}
                      <td className="py-3.5 px-2">
                        {getSeverityBadge(ioc.severity, ioc.isValid)}
                      </td>

                      {/* Confidence Score percentage */}
                      <td className="py-3.5 px-2 text-center">
                        <span className={`font-mono text-xs font-bold ${
                          ioc.confidence >= 90 ? 'text-red-400' : ioc.confidence >= 75 ? 'text-amber-400' : 'text-slate-400'
                        }`}>
                          {ioc.confidence}%
                        </span>
                      </td>

                      {/* Number of Feeds supporting this threat */}
                      <td className="py-3.5 px-2 font-mono text-slate-400">
                        <span className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                          ioc.sources.length >= 3 
                            ? 'bg-red-950 text-red-400 border border-red-500/30 animate-pulse' 
                            : ioc.sources.length === 2 
                            ? 'bg-amber-950 text-amber-400 border border-amber-500/30' 
                            : 'bg-slate-900 text-slate-400'
                        }`}>
                          {ioc.sources.length} Feed{ioc.sources.length > 1 ? 's' : ''}
                        </span>
                      </td>

                      {/* Quick Interactive Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            id={`copy-ioc-btn-${ioc.id}`}
                            onClick={() => handleCopy(ioc.value)}
                            className="p-1 px-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                            title="Copy indicator value"
                          >
                            <Copy size={11} />
                          </button>
                          {ioc.isValid ? (
                            <button
                              id={`dismiss-ioc-btn-${ioc.id}`}
                              onClick={() => onDismissIOC(ioc.id)}
                              className="p-1 px-1.5 rounded bg-slate-800 hover:bg-red-950 hover:text-red-400 text-slate-400 transition-colors border border-transparent hover:border-red-500/20"
                              title="Dismiss and Flag as Safe / Excluded"
                            >
                              <Trash size={11} />
                            </button>
                          ) : (
                            <button
                              id={`restore-ioc-btn-${ioc.id}`}
                              onClick={() => onRestoreIOC(ioc.id)}
                              className="p-1 px-1.5 rounded bg-slate-800 hover:bg-emerald-950 hover:text-emerald-400 text-slate-400 transition-colors border border-transparent hover:border-emerald-500/20"
                              title="Re-validate and flag as threat"
                            >
                              <RefreshCw size={11} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Meta details row */}
                    {isExpanded && (
                      <tr id={`ioc-expanded-${ioc.id}`} className="bg-slate-950/55">
                        <td colSpan={7} className="p-4 border-l-2 border-teal-500 font-mono text-[11px]">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <h4 className="text-[10px] text-slate-500 uppercase font-black uppercase tracking-wider">Indicator Payload Metadata</h4>
                              <div>
                                <span className="text-slate-400">UUID Tag:</span> <span className="text-teal-400 font-semibold select-all">{ioc.id}</span>
                              </div>
                              <div>
                                <span className="text-slate-400">Timestamp:</span> <span className="text-slate-300">{new Date(ioc.timestamp).toLocaleString()}</span>
                              </div>
                              <div>
                                <span className="text-slate-400">Standard Category:</span> <span className="text-slate-300">{ioc.category}</span>
                              </div>
                              <div>
                                <span className="text-slate-400">Validation State:</span>{' '}
                                <span className={ioc.isValid ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                                  {ioc.isValid ? '✓ Validated Public Cyber Threat' : '✗ Scrubbed / Filtered'}
                                </span>
                              </div>
                              {ioc.notes && (
                                <div className="p-2 rounded bg-red-950/20 border border-red-500/10 text-red-400">
                                  <strong>Scrub Reason:</strong> {ioc.notes}
                                </div>
                              )}
                            </div>
                            <div className="space-y-2">
                              <h4 className="text-[10px] text-slate-500 uppercase font-black uppercase tracking-wider">Intel Provenance & Matches</h4>
                              <div>
                                <span className="text-slate-400">Originated In:</span> <span className="text-slate-300 font-medium">{ioc.source}</span>
                              </div>
                              <div>
                                <span className="text-slate-400">Participating Sources:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {ioc.sources.map(src => (
                                    <span key={src} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 select-all border border-slate-700">
                                      {src}
                                    </span>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-400">Analyst Advisory / Description:</span>
                                <p className="text-xs text-slate-300 leading-relaxed mt-1 p-2 border border-slate-800 rounded bg-slate-900/60 font-sans">
                                  {ioc.description}
                                </p>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
