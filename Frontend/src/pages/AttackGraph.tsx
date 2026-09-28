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

const TYPE_META: Record<string, { bg: string; border: string; text: string; icon: string; label: string }> = {
  REPO: { bg: '#1e2530', border: '#3c494e', text: '#cbd5da', icon: 'code_blocks', label: 'Dépôt' },
  SECRET: { bg: '#3a1420', border: '#ff6b6b', text: '#ffb4ab', icon: 'key', label: 'Secret exposé' },
  CVE: { bg: '#3a2410', border: '#ffb020', text: '#ffd699', icon: 'bug_report', label: 'CVE exploitable' },
  SERVER: { bg: '#0f2a2f', border: '#00d1ff', text: '#a4e6ff', icon: 'dns', label: 'Serveur' },
  HARDENING: { bg: '#2a2410', border: '#f5c518', text: '#f5e1a4', icon: 'warning', label: 'Config faible' },
};

const COLUMN_X: Record<string, number> = {
  REPO: 0,
  SECRET: 380,
  CVE: 380,
  SERVER: 820,
  HARDENING: 1260,
};

const ROW_GAP = 140;
const NODE_WIDTH = 300;

function layoutNodes(nodes: AttackGraphNodeDto[]): Node[] {
  const columnCounters: Record<string, number> = {};
  return nodes.map((n) => {
    const col = COLUMN_X[n.type] ?? 0;
    const idx = columnCounters[n.type] ?? 0;
    columnCounters[n.type] = idx + 1;
    const meta = TYPE_META[n.type] ?? TYPE_META.REPO;
    const critical = n.type === 'SERVER' && n.critical;
    return {
      id: n.id,
      position: { x: col, y: idx * ROW_GAP },
      data: {
        label: (
          <div className="flex items-start gap-2 text-left">
            <span className="material-symbols-outlined text-[16px] shrink-0 mt-0.5">{meta.icon}</span>
            <div className="min-w-0">
              <div className="text-[9px] font-bold uppercase tracking-wider opacity-70">
                {meta.label}{critical ? ' · critique' : ''}
              </div>
              <div className="text-[11px] font-semibold leading-snug break-words whitespace-normal">
                {n.label}
              </div>
            </div>
          </div>
        ),
      },
      style: {
        background: meta.bg,
        border: `2px solid ${critical ? '#ff4d4f' : meta.border}`,
        color: meta.text,
        borderRadius: 12,
        padding: '10px 12px',
        width: NODE_WIDTH,
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
      type: 'smoothstep',
      animated: attackEdge,
      style: {
        stroke: attackEdge ? '#ff4d4f' : amplifier ? '#f5c518' : '#3c494e',
        strokeWidth: attackEdge ? 2.5 : amplifier ? 1.5 : 1,
        strokeDasharray: amplifier ? '4 4' : undefined,
        opacity: e.kind === 'CONTAINS' || e.kind === 'DEPLOYS' ? 0.3 : 1,
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

const LEGEND_ITEMS = [
  { key: 'REPO', desc: 'Dépôt de code source' },
  { key: 'SECRET', desc: 'Identifiant exposé dans le code' },
  { key: 'CVE', desc: 'Vulnérabilité exécutable à distance' },
  { key: 'SERVER', desc: 'Serveur déployé (rouge = production)' },
  { key: 'HARDENING', desc: 'Mauvaise configuration serveur' },
];

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

  // When there are no ranked attack paths, explain WHY instead of just saying "none" —
  // distinguish "nothing risky at all" from "weak configs exist but nothing chains to them yet".
  const hardeningOnCriticalCount = useMemo(() => {
    if (paths.length > 0) return 0;
    const criticalServerIds = new Set(
      rawNodes.filter(n => n.type === 'SERVER' && n.critical).map(n => n.id)
    );
    return rawEdges.filter(e => e.kind === 'HARDENING_AMPLIFIER' && criticalServerIds.has(e.target)).length;
  }, [paths.length, rawNodes, rawEdges]);

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
        <>
          {/* Legend */}
          <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-4 flex flex-wrap gap-x-6 gap-y-2">
            {LEGEND_ITEMS.map((item) => {
              const meta = TYPE_META[item.key];
              return (
                <div key={item.key} className="flex items-center gap-2 text-xs">
                  <span
                    className="w-3 h-3 rounded-full shrink-0 border-2"
                    style={{ background: meta.bg, borderColor: meta.border }}
                  />
                  <span className="text-on-surface-variant font-medium">{meta.label}</span>
                  <span className="text-outline text-[10px]">— {item.desc}</span>
                </div>
              );
            })}
            <div className="flex items-center gap-2 text-xs">
              <span className="w-5 h-0.5 bg-error inline-block" />
              <span className="text-on-surface-variant font-medium">Accès / compromission</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="w-5 h-0.5 border-t-2 border-dashed inline-block" style={{ borderColor: '#f5c518' }} />
              <span className="text-on-surface-variant font-medium">Facteur aggravant (mauvaise config)</span>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 glass-panel rounded-3xl border border-outline-variant/[0.18] overflow-hidden" style={{ height: 640 }}>
              <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                fitView
                fitViewOptions={{ padding: 0.25 }}
                minZoom={0.2}
                nodesDraggable
                nodesConnectable={false}
                proOptions={{ hideAttribution: true }}
              >
                <Background color="#3c494e" gap={20} />
                <Controls />
                <MiniMap
                  style={{ background: '#12161c' }}
                  nodeColor={(n) => {
                    const type = (n.id.split('-')[0] || '').toUpperCase();
                    return TYPE_META[type]?.border ?? '#3c494e';
                  }}
                  maskColor="rgba(0,0,0,0.6)"
                />
              </ReactFlow>
            </div>

            <div className="glass-panel rounded-3xl border border-outline-variant/[0.18] p-5 space-y-3 overflow-y-auto" style={{ maxHeight: 640 }}>
              <h3 className="font-headline text-lg font-bold text-on-surface">Chemins d'attaque classés</h3>
              {paths.length === 0 ? (
                <div className="text-sm text-outline py-6 text-center space-y-2">
                  {hardeningOnCriticalCount > 0 ? (
                    <>
                      <p>
                        Aucun secret ni CVE exploitable ne chaîne vers un actif critique pour
                        l'instant.
                      </p>
                      <p className="text-amber-300 text-xs">
                        {hardeningOnCriticalCount} faiblesse{hardeningOnCriticalCount > 1 ? 's' : ''} de
                        configuration détectée{hardeningOnCriticalCount > 1 ? 's' : ''} sur un actif
                        critique — à corriger en prévention (elles amplifieraient un futur accès).
                      </p>
                    </>
                  ) : (
                    <p>Aucun chemin d'attaque détecté vers un actif de production.</p>
                  )}
                </div>
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
        </>
      )}
    </div>
  );
};

export default AttackGraph;
