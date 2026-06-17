import React, { useMemo, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { permissionLabelMap } from '../../constants/access';
import { type AdminPanelContextValue } from '../AdminPanel';
import ConfirmModal from '../../components/ConfirmModal';

const AdminUsersPage: React.FC = () => {
  const {
    users,
    accessRoles,
    loading,
    userForm,
    editingUserId,
    setUserForm,
    startEditingUser,
    cancelEditingUser,
    handleSaveUser,
    handleDeleteUser,
    handleToggleUserSuspension,
  } = useOutletContext<AdminPanelContextValue>();
  const { user } = useAuth();

  const [modal, setModal] = useState<{ open: boolean; title: string; message: string; danger: boolean; onConfirm: () => void }>({
    open: false, title: '', message: '', danger: false, onConfirm: () => {},
  });
  const closeModal = () => setModal(m => ({ ...m, open: false }));

  const selectedAccessRole = useMemo(
    () => accessRoles.find((entry) => String(entry.id) === userForm.accessRoleId) ?? accessRoles[0] ?? null,
    [accessRoles, userForm.accessRoleId],
  );
  const currentUserId = Number(user?.id ?? 0);

  const handleConfirmDelete = (id: number) => {
    setModal({
      open: true,
      title: 'Supprimer le compte',
      message: 'Supprimer ce compte ? Cette action est définitive.',
      danger: true,
      onConfirm: async () => { closeModal(); await handleDeleteUser(id); },
    });
  };

  const handleConfirmSuspension = (id: number, suspended: boolean) => {
    const message = suspended
      ? 'Suspendre ce compte ? La connexion sera bloquée.'
      : 'Réactiver ce compte ?';
    setModal({
      open: true,
      title: suspended ? 'Suspendre le compte' : 'Réactiver le compte',
      message,
      danger: suspended,
      onConfirm: async () => { closeModal(); await handleToggleUserSuspension(id, suspended); },
    });
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
      <ConfirmModal
        open={modal.open}
        title={modal.title}
        message={modal.message}
        danger={modal.danger}
        confirmLabel={modal.danger ? 'Supprimer' : 'Confirmer'}
        onConfirm={modal.onConfirm}
        onCancel={closeModal}
      />
      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div>
          <h2 className="font-headline text-xl font-semibold text-on-surface">{editingUserId ? 'Modifier un compte' : 'Creer un utilisateur'}</h2>
          <p className="mt-2 text-sm text-on-surface-variant">Les comptes applicatifs restent separes des dossiers projets clients, avec edition directe du role d\'acces.</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <input value={userForm.login} onChange={(e) => setUserForm((prev) => ({ ...prev, login: e.target.value }))} placeholder="login interne (optionnel)" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
          <input value={userForm.name} onChange={(e) => setUserForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="nom" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
          <input value={userForm.email} onChange={(e) => setUserForm((prev) => ({ ...prev, email: e.target.value }))} placeholder="email" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
          <input
            type="password"
            value={userForm.password}
            onChange={(e) => setUserForm((prev) => ({ ...prev, password: e.target.value }))}
            placeholder={editingUserId ? 'laisser vide pour conserver le mot de passe' : 'mot de passe'}
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm"
          />
          <select value={userForm.accessRoleId} onChange={(e) => setUserForm((prev) => ({ ...prev, accessRoleId: e.target.value }))} className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm sm:col-span-2">
            {accessRoles.map((role) => (
              <option key={role.id} value={role.id}>{role.name}</option>
            ))}
          </select>
        </div>

        <div className="rounded-2xl bg-surface-container-high px-4 py-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Acces prevus pour le role selectionne</p>
              <p className="mt-2 font-headline text-sm font-semibold text-on-surface">{selectedAccessRole?.name ?? 'Aucun role'}</p>
            </div>
            {selectedAccessRole && (
              <span className="rounded-full bg-surface-container px-3 py-1 text-[11px] font-headline text-on-surface">{selectedAccessRole.baseRole}</span>
            )}
          </div>
          <p className="mt-2 text-sm text-on-surface-variant">{selectedAccessRole?.description || 'Ce role definira les modules visibles et les actions disponibles pour ce compte.'}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {selectedAccessRole?.permissions.map((permission) => (
              <span key={permission} className="rounded-full bg-surface-container px-3 py-1 text-[11px] text-on-surface">
                {permissionLabelMap[permission]?.label ?? permission}
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <button onClick={handleSaveUser} className="rounded-2xl bg-primary px-4 py-3 text-sm font-headline font-semibold text-on-primary">
            {editingUserId ? 'Enregistrer les modifications' : 'Creer l\'utilisateur'}
          </button>
          {editingUserId && (
            <button onClick={cancelEditingUser} className="rounded-2xl border border-outline-variant/[0.22] px-4 py-3 text-sm font-headline font-semibold text-on-surface">
              Annuler
            </button>
          )}
        </div>
      </section>

      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-headline text-xl font-semibold text-on-surface">Utilisateurs</h2>
            <p className="mt-2 text-sm text-on-surface-variant">Edition rapide des comptes avec boutons visibles pour modifier, suspendre et supprimer.</p>
          </div>
          <span className="text-xs text-outline">{users.length} comptes</span>
        </div>

        {loading ? (
          <p className="text-sm text-outline">Chargement…</p>
        ) : (
          <div className="space-y-3 max-h-[38rem] overflow-y-auto pr-2">
            {users.map((entry) => (
              <div key={entry.id} className="rounded-2xl bg-surface-container-high p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-headline text-sm font-semibold text-on-surface">{entry.name || entry.login}</p>
                    <span className="rounded-full bg-surface-container px-3 py-1 text-[11px] font-headline text-on-surface">{entry.role}</span>
                    {entry.suspended && (
                      <span className="rounded-full bg-error/15 px-3 py-1 text-[11px] font-headline text-error">Suspendu</span>
                    )}
                  </div>
                  <p className="text-xs text-outline">{entry.login} · {entry.email || 'Email non renseigne'} · {entry.primaryProvider} · Local: {entry.hasLocalPassword ? 'Oui' : 'Non'}</p>
                  <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-on-surface-variant">
                    <span>GitHub: {entry.hasGithubLinked ? 'Oui' : 'Non'}</span>
                    <span>GitLab: {entry.hasGitlabLinked ? 'Oui' : 'Non'}</span>
                    <span>Base: {entry.systemRole}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 self-end md:self-auto">
                  <button
                    type="button"
                    title="Modifier"
                    onClick={() => startEditingUser(entry)}
                    className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-outline-variant/[0.22] bg-surface-container text-on-surface transition-colors hover:border-primary/40 hover:text-primary"
                  >
                    <span className="material-symbols-outlined text-[20px]">edit</span>
                  </button>
                  <button
                    type="button"
                    title={entry.suspended ? 'Reactiver' : 'Suspendre'}
                    disabled={entry.id === currentUserId}
                    onClick={() => handleConfirmSuspension(entry.id, !entry.suspended)}
                    className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-outline-variant/[0.22] bg-surface-container text-on-surface transition-colors hover:border-warning/40 hover:text-warning disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <span className="material-symbols-outlined text-[20px]">{entry.suspended ? 'play_circle' : 'pause_circle'}</span>
                  </button>
                  <button
                    type="button"
                    title="Supprimer"
                    disabled={entry.id === currentUserId}
                    onClick={() => handleConfirmDelete(entry.id)}
                    className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-outline-variant/[0.22] bg-surface-container text-on-surface transition-colors hover:border-error/40 hover:text-error disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <span className="material-symbols-outlined text-[20px]">delete</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

export default AdminUsersPage;