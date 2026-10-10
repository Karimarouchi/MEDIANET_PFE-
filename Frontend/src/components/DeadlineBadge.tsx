import React, { useState } from "react";
import { formatReleaseDeadline } from "../services/api";

/** Days left until an ISO date (yyyy-MM-dd); negative once passed, null when unset or malformed. */
export function daysLeft(iso?: string | null, now: Date = new Date()): number | null {
  const m = iso ? /^(\d{4})-(\d{2})-(\d{2})/.exec(iso) : null;
  if (!m) return null;
  const end = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  return Math.round((end - start) / 86_400_000);
}

export function countdownLabel(left: number | null): string {
  if (left === null) return "";
  if (left < 0) return `${-left} j de retard`;
  if (left === 0) return "Aujourd'hui";
  return `${left} j restants`;
}

const todayIso = () => {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};

/**
 * Project deadline with a live countdown. Red once passed, orange within 7 days. When `onChange` is given the date
 * can be modified in place (pencil button) — used on the project pages.
 */
const DeadlineBadge: React.FC<{
  deadline?: string | null;
  label?: string | null;
  onChange?: (isoDate: string) => void | Promise<void>;
  /** hide the edit control and the "no deadline" hint (compact list cards) */
  compact?: boolean;
}> = ({ deadline, label, onChange, compact }) => {
  const [editing, setEditing] = useState(false);
  const left = daysLeft(deadline);
  const late = left !== null && left < 0;
  const tight = left !== null && left >= 0 && left <= 7;
  const tone = !deadline
    ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
    : late
      ? "border-error/40 bg-error/10 text-error"
      : tight
        ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
        : "border-primary/30 bg-primary/5 text-primary";

  const picker = (
    <input
      type="date"
      autoFocus
      min={todayIso()}
      defaultValue={deadline ?? ""}
      aria-label="Nouvelle deadline"
      onClick={(e) => e.stopPropagation()}
      onChange={async (e) => {
        if (!e.target.value) return;
        await onChange?.(e.target.value);
        setEditing(false);
      }}
      onBlur={() => setEditing(false)}
      className="rounded-md border border-outline-variant/40 bg-surface-container-high px-2 py-1 text-[11px] text-on-surface [color-scheme:dark]"
    />
  );

  if (!deadline) {
    if (compact) return null;
    return (
      <div className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[11px] ${tone}`}>
        <span className="material-symbols-outlined text-[14px]">event_busy</span>
        <span className="truncate">Aucune deadline : le risque de retard n'est pas calculé</span>
        {onChange && <span className="ml-auto">{picker}</span>}
      </div>
    );
  }

  return (
    <div className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[11px] ${tone}`}>
      <span className="material-symbols-outlined text-[14px]">event</span>
      <span className="truncate">
        {label ? `${label} · ` : "Deadline · "}
        {formatReleaseDeadline(deadline)}
      </span>
      <span className="ml-auto font-bold whitespace-nowrap" data-testid="deadline-countdown">
        {countdownLabel(left)}
      </span>
      {onChange && !compact &&
        (editing ? (
          picker
        ) : (
          <button
            type="button"
            title="Modifier la deadline"
            onClick={(e) => {
              e.stopPropagation();
              setEditing(true);
            }}
            className="material-symbols-outlined text-[14px] opacity-70 hover:opacity-100"
          >
            edit_calendar
          </button>
        ))}
    </div>
  );
};

export default DeadlineBadge;
