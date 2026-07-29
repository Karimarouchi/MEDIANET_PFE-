import React, { useEffect, useRef, useState } from "react";

export type RejectReasonModalProps = {
  open: boolean;
  title?: string;
  subtitle?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  placeholder?: string;
  busy?: boolean;
  onConfirm: (comment: string) => void;
  onCancel: () => void;
};

/**
 * In-app modal for optional reject reason (replaces window.prompt).
 * Matches ConfirmModal / Tactical OS dark glass style.
 */
const RejectReasonModal: React.FC<RejectReasonModalProps> = ({
  open,
  title = "Refuser la dérogation",
  subtitle = "Le développeur sera notifié. Aucun commit ne sera effectué.",
  confirmLabel = "Refuser",
  cancelLabel = "Annuler",
  placeholder = "Ex. : version non validée en staging, risque de régression…",
  busy = false,
  onConfirm,
  onCancel,
}) => {
  const [comment, setComment] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!open) {
      setComment("");
      return;
    }
    const t = window.setTimeout(() => textareaRef.current?.focus(), 50);
    return () => window.clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onCancel();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, busy, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.65)", backdropFilter: "blur(6px)" }}
      onClick={() => {
        if (!busy) onCancel();
      }}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="reject-reason-title"
        className="relative w-full max-w-md rounded-2xl border border-error/25 p-6 shadow-2xl"
        style={{
          background: "rgba(18,22,30,0.96)",
          backdropFilter: "blur(24px)",
          boxShadow:
            "0 0 40px rgba(255,180,171,0.12), 0 8px 32px rgba(0,0,0,0.55)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-4 bg-error/10">
          <span className="material-symbols-outlined text-2xl text-error">
            gavel
          </span>
        </div>

        <h3
          id="reject-reason-title"
          className="font-bold font-headline text-on-surface text-lg mb-1"
        >
          {title}
        </h3>
        <p className="text-sm text-on-surface-variant leading-relaxed mb-4">
          {subtitle}
        </p>

        <label className="block text-[11px] font-bold uppercase tracking-widest text-outline mb-2">
          Motif du refus{" "}
          <span className="font-medium normal-case tracking-normal text-outline/70">
            (optionnel)
          </span>
        </label>
        <textarea
          ref={textareaRef}
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          rows={4}
          disabled={busy}
          placeholder={placeholder}
          className="w-full rounded-xl border border-outline-variant/30 bg-surface-container-high px-3 py-2.5 text-sm text-on-surface outline-none focus:border-error/40 resize-none disabled:opacity-60"
        />

        <div className="flex items-center gap-3 justify-end mt-5">
          <button
            type="button"
            disabled={busy}
            onClick={onCancel}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 bg-surface-container hover:bg-surface-container-highest transition-colors disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => onConfirm(comment.trim())}
            className="px-4 py-2 rounded-xl text-sm font-bold bg-error/20 text-error border border-error/30 hover:bg-error/30 transition-colors disabled:opacity-50"
          >
            {busy ? "Refus…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

export default RejectReasonModal;
