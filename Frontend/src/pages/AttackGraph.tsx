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
  type ReleaseReadinessPriority,
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

function toFlowNode(n: AttackGraphNodeDto, x: number, y: number, highlighted: Set<string> | null): Node {
  const meta = TYPE_META[n.type] ?? TYPE_META.REPO;
  const critical = n.type === 'SERVER' && n.critical;
  const isHighlighted = !highlighted || highlighted.has(n.id);
  return {
    id: n.id,
    position: { x, y },
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
      boxShadow: critical
        ? (isHighlighted ? '0 0 22px rgba(255,77,79,0.7)' : '0 0 16px rgba(255,77,79,0.5)')
        : (isHighlighted && highlighted ? '0 0 14px rgba(0,209,255,0.4)' : undefined),
      opacity: isHighlighted ? 1 : 0.2,
      transition: 'opacity 150ms ease, box-shadow 150ms ease',
    },
  };
}

/** Places each repository, its findings and the server's hardening on the same row as that server. */
function layoutNodes(
  nodes: AttackGraphNodeDto[],
  edges: AttackGraphEdgeDto[],
  highlighted: Set<string> | null,
): Node[] {
  const repoServer = new Map<string, string>();
  const childRepo = new Map<string, string>();
  const nodeServer = new Map<string, string>();
  for (const e of edges) {
    if (e.kind === 'DEPLOYS' && !repoServer.has(e.source)) repoServer.set(e.source, e.target);
    if (e.kind === 'CONTAINS' && !childRepo.has(e.target)) childRepo.set(e.target, e.source);
    if (e.kind === 'HARDENING_AMPLIFIER' && !nodeServer.has(e.source)) nodeServer.set(e.source, e.target);
    if ((e.kind === 'SECRET_ACCESS' || e.kind === 'RCE_CVE') && !nodeServer.has(e.source)) {
      nodeServer.set(e.source, e.target);
    }
  }

  type Columns = Record<string, AttackGraphNodeDto[]>;
  const emptyColumns = (): Columns => ({ REPO: [], SECRET: [], CVE: [], SERVER: [], HARDENING: [] });
  const assigned = new Set<string>();
  const bands: Columns[] = [];

  for (const server of nodes.filter((n) => n.type === 'SERVER')) {
    const cols = emptyColumns();
    cols.SERVER.push(server);
    assigned.add(server.id);
    for (const n of nodes) {
      if (n.type === 'REPO' && repoServer.get(n.id) === server.id) {
        cols.REPO.push(n);
        assigned.add(n.id);
      }
    }
    for (const n of nodes) {
      if (n.type !== 'SECRET' && n.type !== 'CVE') continue;
      const viaRepo = childRepo.has(n.id) ? repoServer.get(childRepo.get(n.id) as string) : undefined;
      if (viaRepo === server.id || (!viaRepo && nodeServer.get(n.id) === server.id)) {
        cols[n.type].push(n);
        assigned.add(n.id);
      }
    }
    for (const n of nodes) {
      if (n.type === 'HARDENING' && nodeServer.get(n.id) === server.id) {
        cols.HARDENING.push(n);
        assigned.add(n.id);
      }
    }
    bands.push(cols);
  }

  const leftover = nodes.filter((n) => !assigned.has(n.id));
  if (leftover.length > 0) {
    const cols = emptyColumns();
    for (const n of leftover) {
      (cols[n.type] ?? cols.REPO).push(n);
    }
    bands.push(cols);
  }

  const placed: Node[] = [];
  let bandRow = 0;
  for (const cols of bands) {
    const height = Math.max(1, ...Object.values(cols).map((list) => list.length));
    const row = bandRow;
    for (const [type, list] of Object.entries(cols)) {
      for (let idx = 0; idx < list.length; idx += 1) {
        placed.push(toFlowNode(list[idx], COLUMN_X[type] ?? 0, (row + idx) * ROW_GAP, highlighted));
      }
    }
    bandRow += height;
  }
  return placed;
}

function layoutEdges(edges: AttackGraphEdgeDto[], highlightedEdgeIds: Set<string> | null): Edge[] {
  return edges.map((e) => {
    const attackEdge = e.kind === 'SECRET_ACCESS' || e.kind === 'RCE_CVE';
    const amplifier = e.kind === 'HARDENING_AMPLIFIER';
    const deploys = e.kind === 'DEPLOYS';
    const baseOpacity = e.kind === 'CONTAINS' ? 0.25 : deploys ? 0.65 : 1;
    const isHighlighted = !highlightedEdgeIds || highlightedEdgeIds.has(e.id);
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'smoothstep',
      animated: attackEdge && isHighlighted,
      style: {
        stroke: attackEdge ? '#ff4d4f' : amplifier ? '#f5c518' : deploys ? '#00d1ff' : '#3c494e',
        strokeWidth: isHighlighted ? (attackEdge ? 3 : amplifier ? 2 : deploys ? 2 : 1) : 1,
        strokeDasharray: amplifier ? '4 4' : undefined,
        opacity: isHighlighted ? baseOpacity : baseOpacity * 0.15,
        transition: 'opacity 150ms ease',
      },
      markerEnd: attackEdge
        ? { type: MarkerType.ArrowClosed, color: '#ff4d4f' }
        : deploys
          ? { type: MarkerType.ArrowClosed, color: '#00d1ff' }
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

type PathGroup = { key: string; path: AttackPathDto; count: number };

function groupPaths(paths: AttackPathDto[], nodes: AttackGraphNodeDto[]): PathGroup[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const groups = new Map<string, PathGroup>();
  for (const path of paths) {
    const related = path.nodeIds.map((id) => byId.get(id));
    const entry = related.find((node) => node && (node.type === "SECRET" || node.type === "CVE"));
    const server = related.find((node) => node?.type === "SERVER");
    const key = `${entry?.id ?? path.narrative}|${server?.id ?? ""}|${path.score}`;
    const existing = groups.get(key);
    if (existing) existing.count += 1;
    else groups.set(key, { key, path, count: 1 });
  }
  return Array.from(groups.values());
}

function focusIds(path: AttackPathDto, edges: AttackGraphEdgeDto[]): Set<string> {
  const ids = new Set(path.nodeIds);
  let grew = true;
  while (grew) {
    grew = false;
    for (const edge of edges) {
      const pullsSource = edge.kind === "HARDENING_AMPLIFIER" || edge.kind === "CONTAINS";
      if (pullsSource && ids.has(edge.target) && !ids.has(edge.source)) {
        ids.add(edge.source);
        grew = true;
      }
    }
  }
  return ids;
}

function KevTopFive({ cves }: { cves: ReleaseReadinessPriority[] }) {
  return (
    <section className="rounded-2xl border border-error/25 bg-error/5 p-4 space-y-2">
      <h2 className="text-sm font-headline font-bold text-on-surface">5 CVE KEV les plus graves</h2>
      <p className="text-xs text-on-surface-variant">
        Confirmées exploitées par le catalogue CISA. Classées par gravité, puis par score CVSS.
      </p>
      {cves.length === 0 ? (
        <p className="text-sm text-outline">Aucune CVE KEV sur les dépôts de ce projet.</p>
      ) : (
        <ol className="space-y-2">
          {cves.map((cve, index) => (
            <li key={`${cve.cveId}-${cve.packageName ?? index}`} className="text-sm text-on-surface">
              <span className="font-mono font-bold text-error">{index + 1}. {cve.cveId}</span>
              {cve.severity ? <span className="text-outline"> · {cve.severity}</span> : null}
              {cve.cvssScore != null ? <span className="text-outline"> · CVSS {cve.cvssScore}</span> : null}
              {cve.packageName ? <span className="block text-xs text-on-surface-variant">{cve.packageName}</span> : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** Attack map. With a clientId it shows only what is related to that project (repos, servers, secrets, CVEs). */
const AttackGraph: React.FC<{
  clientId?: number;
  onOpenServers?: () => void;
  kevCves?: ReleaseReadinessPriority[];
}> = ({ clientId, onOpenServers, kevCves = [] }) => {
  const [rawNodes, setRawNodes] = useState<AttackGraphNodeDto[]>([]);
  const [rawEdges, setRawEdges] = useState<AttackGraphEdgeDto[]>([]);
  const [paths, setPaths] = useState<AttackPathDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [kindFilter, setKindFilter] = useState<"all" | "SECRET" | "CVE">("all");
  const [serverFilter, setServerFilter] = useState<string>("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([getAttackGraph(clientId), getAttackPaths(undefined, clientId)])
      .then(([graphRes, pathsRes]) => {
        if (!active) return;
        setRawNodes(graphRes.data.nodes);
        setRawEdges(graphRes.data.edges);
        setPaths(pathsRes.data);
        setSelectedPathId(pathsRes.data[0]?.id ?? null);
        setShowAll(pathsRes.data.length === 0);
      })
      .catch(() => { if (active) setError("Impossible de charger la cartographie d'attaque."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [clientId]);

  const nodesById = useMemo(() => new Map(rawNodes.map((node) => [node.id, node])), [rawNodes]);
  const servers = rawNodes.filter((node) => node.type === "SERVER");

  const groups = useMemo(() => {
    const matching = paths.filter((path) => {
      if (serverFilter && !path.nodeIds.includes(serverFilter)) return false;
      if (kindFilter === "all") return true;
      return path.nodeIds.some((id) => nodesById.get(id)?.type === kindFilter);
    });
    return groupPaths(matching, rawNodes);
  }, [paths, rawNodes, nodesById, kindFilter, serverFilter]);

  const selectedPath = useMemo(
    () => paths.find((path) => path.id === selectedPathId) ?? groups[0]?.path ?? null,
    [paths, selectedPathId, groups],
  );

  const focused = !showAll && selectedPath ? focusIds(selectedPath, rawEdges) : null;
  const visibleNodes = focused ? rawNodes.filter((node) => focused.has(node.id)) : rawNodes;
  const visibleEdges = focused
    ? rawEdges.filter((edge) => focused.has(edge.source) && focused.has(edge.target))
    : rawEdges;

  const highlightedNodeIds = useMemo(
    () => (showAll && selectedPath ? new Set(selectedPath.nodeIds) : null),
    [showAll, selectedPath],
  );
  const highlightedEdgeIds = useMemo(() => {
    if (!showAll || !selectedPath) return null;
    const nodeIds = new Set(selectedPath.nodeIds);
    return new Set(rawEdges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)).map((edge) => edge.id));
  }, [showAll, selectedPath, rawEdges]);

  const flowNodes = useMemo(
    () => layoutNodes(visibleNodes, visibleEdges, highlightedNodeIds),
    [visibleNodes, visibleEdges, highlightedNodeIds],
  );
  const flowEdges = useMemo(
    () => layoutEdges(visibleEdges, highlightedEdgeIds),
    [visibleEdges, highlightedEdgeIds],
  );

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

  const hardeningNotes = useMemo(() => {
    const rank = (severity: string | null) => (severity === "CRITICAL" ? 0 : severity === "WARNING" ? 1 : 2);
    return rawNodes
      .filter((node) => node.type === "HARDENING")
      .slice()
      .sort((a, b) => rank(a.severity) - rank(b.severity) || a.label.localeCompare(b.label, "fr"));
  }, [rawNodes]);

  return (
    <div className="space-y-6">
      <header>
        {!clientId && (
          <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight mb-2">
            Cartographie d'attaque
          </h1>
        )}
        <p className="text-on-surface-variant text-sm max-w-2xl">
          Un chemin relie un secret ou une CVE exécutable à distance à un serveur de production.
          Le score monte si la CVE est dans le catalogue KEV, si un exploit public existe, et si le serveur est mal configuré.
        </p>
      </header>

      <KevTopFive cves={kevCves} />

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <span className="material-symbols-outlined text-5xl text-primary animate-spin">progress_activity</span>
        </div>
      ) : error ? (
        <p className="text-sm text-error text-center py-12">{error}</p>
      ) : rawNodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-outline space-y-4">
          <p className="text-lg font-headline text-on-surface">Aucune cartographie pour l'instant</p>
          <p className="text-sm max-w-md text-center">
            {clientId
              ? "Aucun dépôt n'est déployé sur un serveur de ce projet."
              : "Ajoutez un dépôt déployé sur un serveur, puis lancez un scan."}
          </p>
          {onOpenServers && (
            <button
              type="button"
              onClick={onOpenServers}
              className="mt-1 flex items-center gap-2 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-on-primary hover:opacity-90"
            >
              <span className="material-symbols-outlined text-base">dns</span>
              Aller aux serveurs
            </button>
          )}
        </div>
      ) : (
        <>
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

          <div className="flex flex-wrap gap-2">
            {LEGEND_ITEMS.map((item) => {
              const meta = TYPE_META[item.key];
              return (
                <span key={item.key} className="inline-flex items-center gap-2 rounded-full border border-outline-variant/20 bg-surface-container px-3 py-1 text-[11px] text-on-surface-variant">
                  <span className="w-2.5 h-2.5 rounded-full border-2" style={{ background: meta.bg, borderColor: meta.border }} />
                  {meta.label}
                </span>
              );
            })}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 glass-panel rounded-3xl border border-outline-variant/[0.18] overflow-hidden flex flex-col" style={{ height: 640 }}>
              <div className="flex items-center justify-between gap-3 border-b border-outline-variant/15 px-4 py-2">
                <p className="text-xs text-outline">{showAll ? "Graphe complet" : "Chemin sélectionné"}</p>
                {paths.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setShowAll((current) => !current)}
                    className="rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-[11px] font-semibold text-primary hover:bg-primary/20"
                  >
                    {showAll ? "Voir ce chemin" : "Voir tout le graphe"}
                  </button>
                )}
              </div>
              <div className="min-h-0 flex-1">
              <ReactFlow
                key={`${showAll ? "all" : "path"}-${selectedPath?.id ?? "none"}`}
                nodes={flowNodes}
                edges={flowEdges}
                fitView
                fitViewOptions={{ padding: 0.3 }}
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
            </div>

            <div className="glass-panel rounded-3xl border border-outline-variant/[0.18] p-5 space-y-3 overflow-y-auto" style={{ maxHeight: 640 }}>
              <div>
                <h3 className="font-headline text-lg font-bold text-on-surface">Chemins d'attaque classés</h3>
                <p className="text-[11px] text-outline mt-0.5">
                  Seuls les serveurs de production entrent dans ce classement. Le plus grave est en haut.
                  {groups.length > 0 ? " Cliquez un chemin pour l'afficher en grand." : ""}
                </p>
              </div>
              {paths.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {([
                    ["all", "Tous"],
                    ["SECRET", "Secrets"],
                    ["CVE", "CVE"],
                  ] as const).map(([value, label]) => (
                    <button
                      key={value}
                      type="button"
                      aria-pressed={kindFilter === value}
                      onClick={() => setKindFilter(value)}
                      className={`rounded-full border px-3 py-1 text-[11px] font-semibold ${
                        kindFilter === value
                          ? "border-primary/40 bg-primary/15 text-primary"
                          : "border-outline-variant/30 text-outline hover:text-on-surface"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              )}
              {servers.length > 1 && (
                <label className="block">
                  <span className="sr-only">Serveur</span>
                  <select
                    value={serverFilter}
                    onChange={(event) => setServerFilter(event.target.value)}
                    className="w-full rounded-xl border border-outline-variant/30 bg-surface-container-high px-3 py-2 text-xs text-on-surface [color-scheme:dark]"
                  >
                    <option value="">Tous les serveurs</option>
                    {servers.map((server) => (
                      <option key={server.id} value={server.id}>{server.label}</option>
                    ))}
                  </select>
                </label>
              )}
              {groups.length === 0 ? (
                <div className="text-sm text-outline py-6 text-center space-y-2">
                  {paths.length > 0 ? (
                    <p>Aucun chemin pour ce filtre.</p>
                  ) : hardeningNotes.length > 0 ? (
                    <>
                      <p>
                        {hardeningOnCriticalCount > 0
                          ? "Aucun secret ni CVE exploitable ne chaîne vers un actif critique pour l'instant."
                          : "Aucun secret ni CVE exploitable ne chaîne vers ce serveur pour l'instant."}
                      </p>
                      <p className="text-amber-300 text-xs">
                        {hardeningNotes.length} faiblesse{hardeningNotes.length > 1 ? "s" : ""} de configuration
                        {hardeningOnCriticalCount > 0 ? " sur un actif critique" : ""}. Elles amplifieraient un futur accès.
                      </p>
                      <ul className="space-y-1.5 text-left pt-1">
                        {hardeningNotes.map((note) => (
                          <li key={note.id} className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300">
                              {note.severity === "CRITICAL" ? "Critique" : "À corriger"}
                            </span>
                            <span className="mt-0.5 block text-xs text-on-surface">{note.label}</span>
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <p>Aucun chemin d'attaque détecté vers un actif de production.</p>
                  )}
                </div>
              ) : (
                <div className="space-y-2">
                  {groups.map((group) => {
                    const isSelected = group.path.id === selectedPath?.id;
                    return (
                      <button
                        key={group.key}
                        type="button"
                        onClick={() => {
                          const topId = groups[0]?.path.id ?? null;
                          if (isSelected) {
                            if (group.path.id === topId) setShowAll((current) => !current);
                            else {
                              setShowAll(false);
                              setSelectedPathId(topId);
                            }
                            return;
                          }
                          setShowAll(false);
                          setSelectedPathId(group.path.id);
                        }}
                        className={`w-full text-left rounded-2xl border p-3 space-y-1.5 transition-colors ${
                          isSelected
                            ? 'border-primary/60 bg-primary/10'
                            : 'border-outline-variant/[0.1] bg-surface-container/40 hover:border-outline-variant/[0.3]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold border ${severityChipClass(group.path.score)}`}>
                            Score {group.path.score}
                          </span>
                          {group.count > 1 && (
                            <span className="text-[10px] font-bold text-outline">{group.count} chemins identiques</span>
                          )}
                        </div>
                        <p className="text-xs text-on-surface-variant leading-snug">{group.path.narrative}</p>
                      </button>
                    );
                  })}
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
