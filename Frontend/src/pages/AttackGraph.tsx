import React, { useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  getAttackGraph,
  getAttackPaths,
  type AttackGraphNodeDto,
  type AttackGraphEdgeDto,
  type AttackPathDto,
} from '../services/api';

const TYPE_COLOR: Record<string, { bg: string; border: string; text: string }> = {
  REPO: { bg: '#1e2530', border: '#3c494e', text: '#cbd5da' },
  SECRET: { bg: '#3a1420', border: '#ff6b6b', text: '#ffb4ab' },
  CVE: { bg: '#3a2410', border: '#ffb020', text: '#ffd699' },
  SERVER: { bg: '#0f2a2f', border: '#00d1ff', text: '#a4e6ff' },
  HARDENING: { bg: '#2a2410', border: '#f5c518', text: '#f5e1a4' },
};

const COLUMN_X: Record<string, number> = {
  REPO: 0,
  SECRET: 320,
  CVE: 320,
  SERVER: 680,
  HARDENING: 1020,
};

function layoutNodes(nodes: AttackGraphNodeDto[]): Node[] {
  const columnCounters: Record<string, number> = {};
  return nodes.map((n) => {
    const col = COLUMN_X[n.type] ?? 0;
    const idx = columnCounters[n.type] ?? 0;
    columnCounters[n.type] = idx + 1;
    const colors = TYPE_COLOR[n.type] ?? TYPE_COLOR.REPO;
    const critical = n.type === 'SERVER' && n.critical;
    return {
      id: n.id,
      position: { x: col, y: idx * 110 },
      data: { label: n.label },
      style: {
        background: colors.bg,
        border: `2px solid ${critical ? '#ff4d4f' : colors.border}`,
        color: colors.text,
        borderRadius: 12,
        padding: '8px 12px',
        fontSize: 11,
        fontWeight: 600,
        width: 220,
        boxShadow: critical ? '0 0 16px rgba(255,77,79,0.5)' : undefined,
      },
    };
  });
}

function layoutEdges(edges: AttackGraphEdgeDto[]): Edge[] {
  return edges.map((e) => {
    const attackEdge = e.kind === 'SECRET_ACCESS' || e.kind === 'RCE_CVE';
    const amplifier = e.kind === 'HARDENING_AMPLIFIER';
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      animated: attackEdge,
      label: attackEdge || amplifier ? e.label : undefined,
      style: {
        stroke: attackEdge ? '#ff4d4f' : amplifier ? '#f5c518' : '#3c494e',
        strokeWidth: attackEdge ? 2.5 : amplifier ? 1.5 : 1,
        strokeDasharray: amplifier ? '4 4' : undefined,
        opacity: e.kind === 'CONTAINS' || e.kind === 'DEPLOYS' ? 0.35 : 1,
      },
      markerEnd: attackEdge
        ? { type: MarkerType.ArrowClosed, color: '#ff4d4f' }
        : undefined,
    };
  });
}

function severityChipClass(score: number) {
  if (score >= 14) return 'bg-error/15 text-error border-error/30';
  if (score >= 9) return 'bg-orange-400/15 text-orange-300 border-orange-400/30';
  return 'bg-amber-300/15 text-amber-300 border-amber-300/30';
}

const AttackGraph: React.FC = () => {
  const [rawNodes, setRawNodes] = useState<AttackGraphNodeDto[]>([]);
  const [rawEdges, setRawEdges] = useState<AttackGraphEdgeDto[]>([]);
  const [paths, setPaths] = useState<AttackPathDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([getAttackGraph(), getAttackPaths()])
      .then(([graphRes, pathsRes]) => {
        if (!active) return;
        setRawNodes(graphRes.data.nodes);
        setRawEdges(graphRes.data.edges);
        setPaths(pathsRes.data);
      })
      .catch(() => { if (active) setError("Impossible de charger la cartographie d'attaque."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const flowNodes = useMemo(() => layoutNodes(rawNodes), [rawNodes]);
  const flowEdges = useMemo(() => layoutEdges(rawEdges), [rawEdges]);

  const criticalServerCount = rawNodes.filter(n => n.type === 'SERVER' && n.critical).length;
  const entryCount = rawNodes.filter(n => n.type === 'SECRET' || n.type === 'CVE').length;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight mb-2">
          Cartographie d'attaque
        </h1>
        <p className="text-on-surface-variant text-sm max-w-2xl">
          Chaîne les secrets exposés et les CVE exploitables à distance jusqu'aux serveurs de
          production, pour prioriser la remédiation par risque réel de compromission plutôt que
          par score CVSS isolé.
        </p>
      </header>

      <div className="grid grid-cols-3 gap-4">
        <div className="glass-panel rounded-xl border border-outline-variant/[0.1] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-on-surface">{entryCount}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Points d'entrée</p>
        </div>
        <div className="glass-panel rounded-xl border border-error/[0.15] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-error">{criticalServerCount}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Actifs critiques</p>
        </div>
        <div className="glass-panel rounded-xl border border-primary/[0.15] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-primary">{paths.length}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Chemins d'attaque</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <span className="material-symbols-outlined text-5xl text-primary animate-spin">progress_activity</span>
        </div>
      ) : error ? (
        <p className="text-sm text-error text-center py-12">{error}</p>
      ) : rawNodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-outline-variant space-y-4">
          <span className="material-symbols-outlined text-6xl">hub</span>
          <p className="text-lg font-headline">Aucune donnée de graphe</p>
          <p className="text-sm max-w-md text-center">
            Il faut au moins un serveur lié à un dépôt (Server Config → lier un dépôt) et un scan
            complété pour construire la cartographie.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 glass-panel rounded-3xl border border-outline-variant/[0.18] overflow-hidden" style={{ height: 560 }}>
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              fitView
              nodesDraggable
              nodesConnectable={false}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#3c494e" gap={20} />
              <Controls />
              <MiniMap
                nodeColor={(n) => {
                  const type = (n.id.split('-')[0] || '').toUpperCase();
                  return TYPE_COLOR[type]?.border ?? '#3c494e';
                }}
                maskColor="rgba(0,0,0,0.6)"
              />
            </ReactFlow>
          </div>

          <div className="glass-panel rounded-3xl border border-outline-variant/[0.18] p-5 space-y-3 overflow-y-auto" style={{ maxHeight: 560 }}>
            <h3 className="font-headline text-lg font-bold text-on-surface">Chemins d'attaque classés</h3>
            {paths.length === 0 ? (
              <p className="text-sm text-outline py-6 text-center">
                Aucun chemin d'attaque détecté vers un actif de production.
              </p>
            ) : (
              <div className="space-y-2">
                {paths.map((p) => (
                  <div key={p.id} className="rounded-2xl border border-outline-variant/[0.1] bg-surface-container/40 p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold border ${severityChipClass(p.score)}`}>
                        Score {p.score}
                      </span>
                    </div>
                    <p className="text-xs text-on-surface-variant leading-snug">{p.narrative}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackGraph;
