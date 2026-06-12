/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { ShieldAlert, TrendingUp } from 'lucide-react';
import { IOC, IOCType } from '../types';

interface ThreatChartsProps {
  iocs: IOC[];
}

export default function ThreatCharts({ iocs }: ThreatChartsProps) {
  const validIOCs = useMemo(() => iocs.filter(ioc => ioc.isValid), [iocs]);

  // Compute Type Distribution for Recharts BarChart
  const typeData = useMemo(() => {
    const counts: { [key in IOCType]?: number } = {};
    validIOCs.forEach(ioc => {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    });

    return Object.entries(counts).map(([type, count]) => ({
      name: type,
      threats: count,
    }));
  }, [validIOCs]);

  // Compute Severity Distribution for Recharts PieChart
  const severityData = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    validIOCs.forEach(ioc => {
      counts[ioc.severity]++;
    });

    const COLORS = {
      Critical: '#ef4444', // red-500
      High: '#f97316',     // orange-500
      Medium: '#eab308',   // yellow-500
      Low: '#94a3b8',      // slate-400
    };

    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([severity, count]) => ({
        name: severity,
        value: count,
        color: COLORS[severity as keyof typeof COLORS] || '#94a3b8',
      }));
  }, [validIOCs]);

  // Custom Tooltip component
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg font-mono text-[11px] shadow-xl">
          <p className="text-slate-400 font-bold uppercase">{payload[0].name}</p>
          <p className="text-sky-400 mt-1">Unique Threats: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-8">
      
      {/* Category distribution - Bar Chart */}
      <div className="lg:col-span-7 bg-[#141415] border border-[#1A1A1C] p-5 flex flex-col justify-between">
        <div>
          <h3 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-[#00F5FF]">02</span> IOC Taxonomies
          </h3>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Breakdown of unique validated cyber indicators.
          </p>
        </div>

        <div className="h-[200px] w-full mt-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={typeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1A1A1C" vertical={false} />
              <XAxis 
                dataKey="name" 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false} 
                axisLine={false}
                fontFamily="SFMono-Regular, ui-monospace, monospace"
                fontWeight="bold"
              />
              <YAxis 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false} 
                axisLine={false}
                fontFamily="SFMono-Regular, ui-monospace, monospace"
                fontWeight="bold"
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1A1A1C' }} />
              <Bar dataKey="threats" radius={0}>
                {typeData.map((entry, index) => {
                  let color = '#00F5FF'; // Default cyan
                  if (entry.name === 'IP') color = '#00F5FF';
                  if (entry.name === 'Domain') color = '#2dd4bf';
                  if (entry.name === 'URL') color = '#a78bfa';
                  if (entry.name === 'Hash') color = '#fbbf24';
                  if (entry.name === 'Email') color = '#fb7185';
                  return <Cell key={`cell-${index}`} fill={color} />;
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Severity breakdown - Pie Chart */}
      <div className="lg:col-span-5 bg-[#141415] border border-[#1A1A1C] p-5 flex flex-col justify-between">
        <div>
          <h3 className="text-xl font-black font-sans text-white uppercase flex items-center gap-2">
            <span className="text-red-400">X</span> Threat Severity
          </h3>
          <p className="text-[10px] text-slate-400 mt-1 uppercase font-mono tracking-widest font-bold">
            Real-time rating consensus.
          </p>
        </div>

        <div className="h-[200px] w-full mt-4 flex items-center justify-center">
          {severityData.length === 0 ? (
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-bold">No active threats loaded</p>
          ) : (
            <div className="w-full h-full flex flex-row items-center justify-between">
              {/* Pie section */}
              <div className="w-1/2 h-full text-center relative flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={2}
                      dataKey="value"
                      stroke="none"
                    >
                      {severityData.map((entry, idx) => (
                        <Cell key={`cell-${idx}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                {/* Center text overlay */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-black font-mono text-white">
                    {validIOCs.length}
                  </span>
                  <span className="text-[10px] font-mono tracking-widest text-[#00F5FF] font-bold uppercase">
                    Threats
                  </span>
                </div>
              </div>

              {/* Legend section */}
              <div className="w-1/2 font-mono text-[10px] uppercase font-bold tracking-widest text-slate-400 space-y-3 pl-4">
                {severityData.map((item, index) => (
                  <div key={item.name} className="flex items-center gap-2">
                    <span className="w-2 h-2 shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="flex-1 truncate">{item.name}</span>
                    <strong className="text-white text-xs">{item.value}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
