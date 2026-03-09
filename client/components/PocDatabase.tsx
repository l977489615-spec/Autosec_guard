import React, { useState, useEffect } from 'react';
import { POC_DATABASE } from '../constants';
import { Category, Severity, POC } from '../types';
import { Search, ShieldAlert, Cpu, Radio, Activity, Cloud, Eye } from 'lucide-react';
import PocDetailModal from './PocDetailModal';
import { listPocs } from '../services/api';

const PocDatabase: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCat, setFilterCat] = useState<string>('All');
  const [selectedPoc, setSelectedPoc] = useState<POC | null>(null);
  const [pocContents, setPocContents] = useState<Record<string, string>>({});

  useEffect(() => {
    const fetchPocs = async () => {
      const data = await listPocs();
      if (data && data.pocs) {
        const contentsMap: Record<string, string> = {};
        data.pocs.forEach((p: any) => {
          const matchingDbPoc = POC_DATABASE.find(db => db.pocFile === p.filename);
          if (matchingDbPoc && p.content) {
            contentsMap[matchingDbPoc.id] = p.content;
          }
        });
        setPocContents(contentsMap);
      }
    };
    fetchPocs();
  }, []);

  const filtered = POC_DATABASE.filter(poc => {
    const matchesSearch = poc.name.toLowerCase().includes(searchTerm.toLowerCase()) || poc.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCat = filterCat === 'All' || poc.category === filterCat;
    return matchesSearch && matchesCat;
  });

  const getSeverityColor = (sev: Severity) => {
    switch (sev) {
      case Severity.CRITICAL: return 'text-cyber-danger border-cyber-danger';
      case Severity.HIGH: return 'text-orange-500 border-orange-500';
      case Severity.MEDIUM: return 'text-cyber-warning border-cyber-warning';
      default: return 'text-cyber-400 border-cyber-400';
    }
  };

  const categories = ['All', ...Object.values(Category)];

  return (
    <div className="p-6 space-y-6">
      <PocDetailModal
        poc={selectedPoc ? { ...selectedPoc, codeSnippet: pocContents[selectedPoc.id] || selectedPoc.codeSnippet } : null}
        isOpen={!!selectedPoc}
        onClose={() => setSelectedPoc(null)}
      />

      <div className="flex flex-col md:flex-row justify-between items-center gap-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="text-cyber-accent" />
          POC Plugin Database ({POC_DATABASE.length})
        </h2>

        <div className="flex gap-4 w-full md:w-auto">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search CVE or POC Name..."
              className="bg-cyber-800 border border-cyber-700 text-white pl-10 pr-4 py-2 rounded-md focus:border-cyber-accent focus:outline-none w-full md:w-64"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <select
            className="bg-cyber-800 border border-cyber-700 text-white px-4 py-2 rounded-md focus:border-cyber-accent outline-none"
            value={filterCat}
            onChange={(e) => setFilterCat(e.target.value)}
          >
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map(poc => (
          <div
            key={poc.id}
            onClick={() => setSelectedPoc(poc)}
            className="bg-cyber-800/50 border border-cyber-700 p-4 rounded-lg hover:border-cyber-500 hover:bg-cyber-800 cursor-pointer transition-all group relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 p-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <Eye size={16} className="text-cyber-accent" />
            </div>
            <div className="flex justify-between items-start mb-2">
              <span className={`text-xs px-2 py-0.5 rounded border ${getSeverityColor(poc.severity)} bg-opacity-10`}>
                {poc.severity}
              </span>
              <span className="text-xs text-gray-500 font-mono">{poc.id}</span>
            </div>
            <h3 className="font-semibold text-gray-100 mb-2 group-hover:text-cyber-accent transition-colors pr-6">{poc.name}</h3>
            <div className="flex items-center gap-2 text-xs text-cyber-400 mb-3">
              {poc.category === Category.IVI && <Cpu size={14} />}
              {poc.category === Category.WIRELESS && <Radio size={14} />}
              {poc.category === Category.CLOUD && <Cloud size={14} />}
              {poc.category === Category.PROTOCOL && <Activity size={14} />}
              {poc.category}
            </div>
            <p className="text-sm text-gray-400 line-clamp-2">{poc.description}</p>
          </div>
        ))}
      </div>
      {filtered.length === 0 && (
        <div className="text-center py-20 text-gray-500">
          No POC plugins found matching your criteria.
        </div>
      )}
    </div>
  );
};

export default PocDatabase;