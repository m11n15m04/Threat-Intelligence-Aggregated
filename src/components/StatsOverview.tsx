/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { motion } from 'motion/react';
import { Network, ShieldAlert, Layers, ShieldCheck, HelpCircle } from 'lucide-react';
import { IOC } from '../types';

interface StatsProps {
  totalFeeds: number;
  activeFeeds: number;
  iocs: IOC[];
}

export default function StatsOverview({ totalFeeds, activeFeeds, iocs }: StatsProps) {
  // Compute analytics
  const totalParsed = iocs.length;
  const validIOCs = iocs.filter(i => i.isValid);
  const totalValid = validIOCs.length;
  
  // High Priority / Critical counts
  const highPriority = validIOCs.filter(i => i.sources.length >= 2).length;
  
  // Whitelisted / Private IOCs
  const filteredCount = iocs.filter(i => !i.isValid).length;

  // Correlation Rate: Percent of valid IOCs that exist in more than 1 feed
  const correlationRate = totalValid > 0 ? ((highPriority / totalValid) * 100).toFixed(1) : '0.0';

  const stats = [
    {
      id: 'active-feeds',
      title: 'Aggregated Feeds',
      value: `${activeFeeds} / ${totalFeeds}`,
      subtitle: `Successfully synchronized`,
      icon: Network,
      color: 'text-sky-400 border-sky-500/20 bg-sky-950/20',
      description: 'Active sources parsed'
    },
    {
      id: 'total-iocs',
      title: 'Unique Threats (Validated)',
      value: totalValid.toLocaleString(),
      subtitle: `Total indicators: ${totalParsed}`,
      icon: ShieldAlert,
      color: 'text-amber-400 border-amber-500/20 bg-amber-950/20',
      description: 'Valid, active threats in system'
    },
    {
      id: 'overlap-threats',
      title: 'Cross-Feed Overlaps',
      value: highPriority.toLocaleString(),
      subtitle: `${correlationRate}% overlap rate`,
      icon: Layers,
      color: 'text-red-400 border-red-500/20 bg-red-950/20',
      description: 'Threats flagged by 2+ distinct feeds'
    },
    {
      id: 'filtered-fp',
      title: 'False Positive Mitigations',
      value: filteredCount.toLocaleString(),
      subtitle: 'RFC 1918 & White-listed',
      icon: ShieldCheck,
      color: 'text-emerald-400 border-emerald-500/20 bg-emerald-950/20',
      description: 'Auto-scrubbed safe elements'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      {stats.map((stat, idx) => {
        const Icon = stat.icon;
        return (
          <motion.div
            id={`stat-card-${stat.id}`}
            key={stat.id}
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: idx * 0.08 }}
            className={`flex flex-col justify-between p-5 rounded-none border border-[#1A1A1C] bg-[#141415] relative overflow-hidden transition-all duration-300 hover:border-slate-700`}
          >
            {/* Subtle glow background */}
            <div className={`absolute top-0 right-0 w-24 h-24 rounded-full blur-[40px] opacity-10 pointer-events-none ${stat.color.split(' ')[2]}`} />

            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs font-mono tracking-widest text-[#00F5FF] font-bold uppercase">{stat.title}</p>
                <h3 className="text-4xl font-black text-white mt-2 tracking-tighter uppercase">
                  {stat.value}
                </h3>
              </div>
              <div className={`p-2.5 rounded-none border ${stat.color.split(' ')[0]} ${stat.color.split(' ')[1]}`}>
                <Icon size={20} className="stroke-[2.5]" />
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-[#1A1A1C] flex items-center justify-between text-[10px] text-slate-500 uppercase tracking-widest font-bold">
              <span>{stat.subtitle}</span>
              <span className="bg-[#1A1A1C] px-2 py-0.5 text-[#00F5FF]">
                {stat.description}
              </span>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
