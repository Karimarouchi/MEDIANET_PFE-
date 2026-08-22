import React from 'react';
import type { ServerNodeRequest } from '../services/api';

export const extractApiError = (err: any, fallback: string) =>
  err?.response?.data?.message || err?.message || fallback;

export const emptyServerForm: ServerNodeRequest = {
  name: '',
  host: '',
  port: 22,
  username: 'root',
  nodeType: 'PRODUCTION',
  authMethod: 'PASSWORD',
  environment: 'LAB',
  templateKey: 'CUSTOM',
  owner: '',
  clientName: '',
  projectName: '',
  runbookUrl: '',
  tags: [],
  notes: '',
  password: '',
  privateKey: '',
  privateKeyPassphrase: '',
  description: '',
  deployPath: '',
  domain: '',
  linkedRepositoryId: null,
  deployBranch: 'main',
  deployStrategy: 'DOCKER_COMPOSE',
};

export const deployStrategyOptions = [
  { value: 'DOCKER_COMPOSE', label: 'Docker Compose', helper: 'git pull + docker compose up -d --build' },
  { value: 'STATIC_NGINX', label: 'Site nginx (HTML / PHP)', helper: 'git pull + nginx -t + reload. Pour Courtlinker et les vitrines.' },
];

export const environmentOptions = [
  { value: 'PRODUCTION', label: 'Production' },
  { value: 'PREPROD', label: 'Préproduction' },
  { value: 'STAGING', label: 'Staging' },
  { value: 'DEVELOPMENT', label: 'Développement' },
  { value: 'LAB', label: 'Lab / Test' },
];

export const serverTemplateOptions = [
  { value: 'CUSTOM', label: 'Custom', helper: 'Saisie libre pour tout environnement.' },
  { value: 'DOCKER_LOCAL', label: 'Docker local', helper: 'localhost:2222, lab local, conteneur de test.' },
  { value: 'LINUX_VM', label: 'VM Linux', helper: 'VM Ubuntu/Debian/CentOS classique.' },
  { value: 'WSL_LOCAL', label: 'WSL local', helper: 'Instance WSL sur poste de développement.' },
  { value: 'CLOUD_VM', label: 'Cloud VM', helper: 'Machine virtuelle cloud accessible en SSH.' },
  { value: 'BARE_METAL', label: 'Bare metal', helper: 'Serveur physique ou appliance dédiée.' },
];

const serverTemplatePresets: Record<string, Partial<ServerNodeRequest>> = {
  CUSTOM: {
    templateKey: 'CUSTOM',
    environment: 'LAB',
    nodeType: 'CUSTOM',
    authMethod: 'PASSWORD',
    username: 'root',
    port: 22,
  },
  DOCKER_LOCAL: {
    templateKey: 'DOCKER_LOCAL',
    environment: 'LAB',
    nodeType: 'CUSTOM',
    authMethod: 'PASSWORD',
    username: 'root',
    host: 'localhost',
    port: 2222,
    tags: ['docker', 'local'],
  },
  LINUX_VM: {
    templateKey: 'LINUX_VM',
    environment: 'STAGING',
    nodeType: 'STAGING',
    authMethod: 'PRIVATE_KEY',
    username: 'ubuntu',
    port: 22,
    tags: ['linux', 'vm'],
  },
  WSL_LOCAL: {
    templateKey: 'WSL_LOCAL',
    environment: 'LAB',
    nodeType: 'CUSTOM',
    authMethod: 'PASSWORD',
    username: 'root',
    host: 'localhost',
    port: 22,
    tags: ['wsl', 'local'],
  },
  CLOUD_VM: {
    templateKey: 'CLOUD_VM',
    environment: 'PRODUCTION',
    nodeType: 'PRODUCTION',
    authMethod: 'PRIVATE_KEY',
    username: 'ubuntu',
    port: 22,
    tags: ['cloud'],
  },
  BARE_METAL: {
    templateKey: 'BARE_METAL',
    environment: 'PRODUCTION',
    nodeType: 'PRODUCTION',
    authMethod: 'PRIVATE_KEY',
    username: 'root',
    port: 22,
    tags: ['bare-metal'],
  },
};

export const parseTagsInput = (value: string) =>
  value
    .split(',')
    .map((tag) => tag.trim())
    .filter((tag) => Boolean(tag));

export const stringifyTags = (tags?: string[] | null) => (tags ?? []).join(', ');

export const applyServerTemplate = (current: ServerNodeRequest, templateKey: string): ServerNodeRequest => {
  const preset = serverTemplatePresets[templateKey] ?? serverTemplatePresets.CUSTOM;

  return {
    ...current,
    ...preset,
    templateKey,
    name: current.name,
    password: current.password,
    privateKey: current.privateKey,
    privateKeyPassphrase: current.privateKeyPassphrase,
    description: current.description,
    owner: current.owner,
    clientName: current.clientName,
    projectName: current.projectName,
    runbookUrl: current.runbookUrl,
    notes: current.notes,
    tags: current.tags && current.tags.length ? current.tags : (preset.tags ?? []),
  };
};

export const validateServerForm = (form: ServerNodeRequest, isEditing: boolean) => {
  const errors: string[] = [];
  const host = form.host.trim();
  const username = form.username.trim();
  const templateKey = form.templateKey?.trim() || 'CUSTOM';

  if (form.name.trim().length < 2) {
    errors.push('Le nom du serveur doit contenir au moins 2 caractères.');
  }
  if (!host) {
    errors.push('L’hôte SSH est requis.');
  }
  if (host.includes(' ')) {
    errors.push('L’hôte SSH ne doit pas contenir d’espaces.');
  }
  if (!Number.isFinite(form.port) || form.port < 1 || form.port > 65535) {
    errors.push('Le port SSH doit être compris entre 1 et 65535.');
  }
  if (username.length < 2 || username.includes(' ')) {
    errors.push('L’utilisateur SSH doit contenir au moins 2 caractères et aucun espace.');
  }
  if (form.runbookUrl && !/^https?:\/\//i.test(form.runbookUrl.trim())) {
    errors.push('Le runbook doit être une URL http:// ou https://.');
  }
  if ((form.tags ?? []).length > 12) {
    errors.push('Limite atteinte: 12 tags maximum par serveur.');
  }
  if (!isEditing && form.authMethod === 'PASSWORD' && !(form.password ?? '').trim()) {
    errors.push('Le mot de passe SSH est obligatoire pour un nouveau serveur en mode mot de passe.');
  }
  if (!isEditing && form.authMethod === 'PRIVATE_KEY' && !(form.privateKey ?? '').trim()) {
    errors.push('La clé privée SSH est obligatoire pour un nouveau serveur en mode clé privée.');
  }
  if (!form.environment?.trim()) {
    errors.push('L’environnement du serveur est obligatoire.');
  }
  if (templateKey === 'CUSTOM' && form.environment === 'LAB' && host.toLowerCase() === 'localhost') {
    errors.push('Choisis un template explicite pour localhost afin de distinguer Docker local et WSL.');
  }

  errors.push(...validateDeployFields(form.deployPath, form.domain, form.deployBranch));

  return errors;
};

export const validateDeployFields = (deployPathRaw?: string | null, domainRaw?: string | null, deployBranchRaw?: string | null) => {
  const errors: string[] = [];
  const deployPath = (deployPathRaw ?? '').trim();
  if (deployPath && (deployPath.length > 255 || !deployPath.startsWith('/') || deployPath.includes('..') || !/^\/[A-Za-z0-9._/-]+$/.test(deployPath))) {
    errors.push('Chemin de déploiement invalide. Utilisez un chemin absolu simple, ex. /var/www/pfe/MEDIANET_PFE-');
  }

  const deployBranch = (deployBranchRaw ?? 'main').trim() || 'main';
  if (!/^[A-Za-z0-9._/-]{1,80}$/.test(deployBranch)) {
    errors.push('Nom de branche invalide. Utilisez uniquement lettres, chiffres, . _ / -');
  }

  const domain = (domainRaw ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (domain && !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$/.test(domain)) {
    errors.push('Domaine invalide. Exemple : pfe.exemple.com');
  }

  return errors;
};

export const FormSection: React.FC<{
  step?: string;
  title: string;
  hint?: string;
  children: React.ReactNode;
}> = ({ step, title, hint, children }) => (
  <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container p-5">
    <div className="mb-4 flex items-start gap-3">
      {step ? (
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-bold text-primary">
          {step}
        </span>
      ) : null}
      <div>
        <h3 className="font-headline text-base font-semibold text-on-surface">{title}</h3>
        {hint ? <p className="mt-1 text-xs text-on-surface-variant">{hint}</p> : null}
      </div>
    </div>
    {children}
  </div>
);

export const FormField: React.FC<{
  label: string;
  hint?: string;
  className?: string;
  children: React.ReactNode;
}> = ({ label, hint, className, children }) => (
  <label className={className ?? ''}>
    <span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.18em] text-outline">{label}</span>
    {children}
    {hint ? <span className="mt-1.5 block text-[11px] text-on-surface-variant">{hint}</span> : null}
  </label>
);

export const fieldClass =
  'w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-low px-4 py-3 text-sm text-on-surface outline-none transition focus:border-primary/45';

export const nodeTypeOptions = [
  { value: 'PRODUCTION', label: 'Production' },
  { value: 'STAGING', label: 'Staging' },
  { value: 'DATABASE', label: 'Database' },
  { value: 'REVERSE_PROXY', label: 'Reverse Proxy' },
  { value: 'SCANNER_NODE', label: 'Scanner Node' },
  { value: 'CUSTOM', label: 'Custom' },
];

export const typeBadgeClass: Record<string, string> = {
  PRODUCTION: 'border-error/30 bg-error/10 text-error',
  STAGING: 'border-secondary/30 bg-secondary/10 text-secondary',
  DATABASE: 'border-primary/30 bg-primary/10 text-primary',
  REVERSE_PROXY: 'border-tertiary/30 bg-tertiary/10 text-tertiary',
  SCANNER_NODE: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
  CUSTOM: 'border-outline-variant/30 bg-surface-container text-on-surface-variant',
};

export const severityBadgeClass: Record<string, string> = {
  CRITICAL: 'border-error/30 bg-error/10 text-error',
  WARNING: 'border-secondary/30 bg-secondary/10 text-secondary',
  INFO: 'border-primary/30 bg-primary/10 text-primary',
};

export const formatNodeType = (value?: string | null) => {
  if (!value) return 'Custom';
  return value.replaceAll('_', ' ').toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
};

export const formatDateTime = (value?: string | null) =>
  value ? new Date(value).toLocaleString('fr-FR') : 'Jamais';

export const MetricCard: React.FC<{ icon: string; label: string; value: string; helper?: string }> = ({
  icon,
  label,
  value,
  helper,
}) => (
  <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container p-5">
    <div className="flex items-center justify-between gap-3">
      <div>
        <p className="text-[11px] uppercase tracking-[0.22em] text-outline">{label}</p>
        <p className="mt-3 font-headline text-lg font-semibold text-on-surface">{value || '—'}</p>
      </div>
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10">
        <span className="material-symbols-outlined text-primary">{icon}</span>
      </div>
    </div>
    {helper ? <p className="mt-3 text-xs text-on-surface-variant">{helper}</p> : null}
  </div>
);