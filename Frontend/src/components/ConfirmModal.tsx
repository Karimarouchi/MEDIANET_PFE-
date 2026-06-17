import React, { useEffect } from 'react';

interface ConfirmModalProps {
  open: boolean;
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  open,
  title = 'Confirmation',
  message,
  confirmLabel = 'Confirmer',
  cancelLabel = 'Annuler',
  danger = false,
  onConfirm,
  onCancel,
}) => {
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (!open) return;
      if (e.key === 'Escape') onCancel();
      if (e.key === 'Enter') onConfirm();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [open, onConfirm, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
      onClick={onCancel}
    >
      <div
        className="relative w-full max-w-sm mx-4 rounded-2xl border border-outline-variant/20 p-6 shadow-2xl"
        style={{
          background: 'rgba(18,22,30,0.95)',
          backdropFilter: 'blur(24px)',
          boxShadow: danger
            ? '0 0 40px rgba(255,180,171,0.12), 0 8px 32px rgba(0,0,0,0.5)'
            : '0 0 40px rgba(164,230,255,0.08), 0 8px 32px rgba(0,0,0,0.5)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Icon */}
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-4 ${danger ? 'bg-error/10' : 'bg-primary/10'}`}>
          <span className={`material-symbols-outlined text-2xl ${danger ? 'text-error' : 'text-primary'}`}>
            {danger ? 'warning' : 'help'}
          </span>
        </div>

        {/* Title */}
        <h3 className="font-bold font-headline text-on-surface text-lg mb-2">{title}</h3>

        {/* Message */}
        <p className="text-sm text-on-surface-variant leading-relaxed mb-6">{message}</p>

        {/* Actions */}
        <div className="flex items-center gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 bg-surface-container hover:bg-surface-container-highest transition-colors"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 rounded-xl text-sm font-bold transition-colors ${
              danger
                ? 'bg-error/20 text-error border border-error/30 hover:bg-error/30'
                : 'bg-primary/20 text-primary border border-primary/30 hover:bg-primary/30'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmModal;
