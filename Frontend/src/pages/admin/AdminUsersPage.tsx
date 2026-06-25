import React, { useMemo, useState, useEffect } from 'react';
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
  
  const [isFormOpen, setIsFormOpen] = useState(false);

  const closeModal = () => setModal(m => ({ ...m, open: false }));
  const currentUserId = Number(user?.id ?? 0);

  const selectedAccessRole = useMemo(
    () => accessRoles.find((entry) => String(entry.id) === userForm.accessRoleId) ?? accessRoles[0] ?? null,
    [accessRoles, userForm.accessRoleId],
  );

  // Synchronize form modal open state with start of user editing
  useEffect(() => {
    if (editingUserId) {
      setIsFormOpen(true);
    }
  }, [editingUserId]);

  // Synchronize form modal close when successfully saved or canceled (form reset)
  useEffect(() => {
    if (!editingUserId && !userForm.name && !userForm.email) {
      setIsFormOpen(false);
    }
  }, [editingUserId, userForm.name, userForm.email]);

  const handleOpenCreateForm = () => {
    cancelEditingUser();
    setIsFormOpen(true);
  };

  const handleCloseForm = () => {
    setIsFormOpen(false);
    cancelEditingUser();
  };

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
    <div className="space-y-6">
      <ConfirmModal
        open={modal.open}
        title={modal.title}
        message={modal.message}
        danger={modal.danger}
        confirmLabel={modal.danger ? 'Supprimer' : 'Confirmer'}
        onConfirm={modal.onConfirm}
        onCancel={closeModal}
      />

      {/* Header and top buttons */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-outline-variant/[0.12] pb-6">
        <div>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Comptes Utilisateurs</h2>
          <p className="mt-1 text-sm text-on-surface-variant">Gérez les comptes d'accès, leurs liaisons Git, et leurs privilèges applicatifs.</p>
        </div>
        <button
          onClick={handleOpenCreateForm}
          className="inline-flex items-center justify-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-bold text-on-primary hover:bg-primary-hover transition-colors shadow-lg shadow-primary/20 self-start sm:self-auto"
        >
          <span className="material-symbols-outlined text-[18px]">person_add</span>
          <span>Créer un utilisateur</span>
        </button>
      </div>

      {/* User cards list */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <span className="animate-spin inline-block h-8 w-8 rounded-full border-4 border-primary border-t-transparent" />
          <p className="ml-3 text-sm text-outline">Chargement des comptes…</p>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {users.map((entry) => {
            const isCurrentUser = entry.id === currentUserId;
            const initials = (entry.name || entry.login || '?').substring(0, 1).toUpperCase();

            return (
              <div
                key={entry.id}
                className={`relative flex flex-col justify-between rounded-3xl border bg-surface-container p-6 space-y-4 hover:border-outline-variant/60 transition-all duration-300 hover:shadow-xl group ${
                  entry.suspended
                    ? 'border-error/20 bg-error/[0.02]'
                    : 'border-outline-variant/[0.18]'
                }`}
              >
                {/* Card Header */}
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    {entry.avatarUrl ? (
                      <img
                        src={entry.avatarUrl}
                        alt={entry.name}
                        className="h-12 w-12 rounded-full object-cover border border-outline-variant/[0.2]"
                      />
                    ) : (
                      <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary/30 to-tertiary/30 border border-primary/20 text-primary font-headline text-lg font-bold">
                        {initials}
                      </div>
                    )}

                    <div className="overflow-hidden">
                      <h3 className="font-headline text-base font-bold text-on-surface line-clamp-1 group-hover:text-primary transition-colors">
                        {entry.name || entry.login}
                      </h3>
                      <p className="text-xs text-outline line-clamp-1">@{entry.login}</p>
                    </div>
                  </div>

                  <div className="flex flex-col gap-1 items-end shrink-0">
                    <span className="rounded-full bg-surface-container-high border border-outline-variant/[0.15] px-2.5 py-0.5 text-[10px] font-headline font-bold text-on-surface-variant">
                      {entry.role}
                    </span>
                    {entry.suspended && (
                      <span className="rounded-full bg-error/10 border border-error/20 px-2.5 py-0.5 text-[10px] font-headline font-bold text-error">
                        Suspendu
                      </span>
                    )}
                    {isCurrentUser && (
                      <span className="rounded-full bg-primary/10 border border-primary/20 px-2.5 py-0.5 text-[10px] font-headline font-bold text-primary">
                        Vous
                      </span>
                    )}
                  </div>
                </div>

                {/* Card Details / Info */}
                <div className="space-y-2 text-xs text-on-surface-variant bg-surface-container-high/40 rounded-2xl p-3.5 border border-outline-variant/[0.08]">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="material-symbols-outlined text-[16px] text-outline">mail</span>
                    <span className="truncate">{entry.email || 'Email non renseigné'}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] text-outline">key</span>
                    <span>Auth : <strong className="text-on-surface font-semibold">{entry.primaryProvider}</strong></span>
                  </div>

                  <div className="flex items-center justify-between border-t border-outline-variant/[0.08] pt-2 mt-2">
                    <div className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${entry.hasGithubLinked ? 'bg-primary shadow-[0_0_8px_rgba(0,209,255,0.4)]' : 'bg-outline/30'}`} />
                      <span>GitHub</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${entry.hasGitlabLinked ? 'bg-primary shadow-[0_0_8px_rgba(0,209,255,0.4)]' : 'bg-outline/30'}`} />
                      <span>GitLab</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${entry.hasLocalPassword ? 'bg-primary shadow-[0_0_8px_rgba(0,209,255,0.4)]' : 'bg-outline/30'}`} />
                      <span>Local</span>
                    </div>
                  </div>
                </div>

                {/* Card Actions */}
                <div className="flex items-center justify-end gap-2 pt-2 border-t border-outline-variant/[0.08]">
                  <button
                    type="button"
                    title="Modifier"
                    onClick={() => startEditingUser(entry)}
                    className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-on-surface transition-colors hover:border-primary/40 hover:text-primary hover:bg-surface-container"
                  >
                    <span className="material-symbols-outlined text-[18px]">edit</span>
                  </button>
                  <button
                    type="button"
                    title={entry.suspended ? 'Réactiver' : 'Suspendre'}
                    disabled={isCurrentUser}
                    onClick={() => handleConfirmSuspension(entry.id, !entry.suspended)}
                    className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-on-surface transition-colors hover:border-warning/40 hover:text-warning hover:bg-surface-container disabled:cursor-not-allowed disabled:opacity-30"
                  >
                    <span className="material-symbols-outlined text-[18px]">
                      {entry.suspended ? 'play_circle' : 'pause_circle'}
                    </span>
                  </button>
                  <button
                    type="button"
                    title="Supprimer"
                    disabled={isCurrentUser}
                    onClick={() => handleConfirmDelete(entry.id)}
                    className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-on-surface transition-colors hover:border-error/40 hover:text-error hover:bg-surface-container disabled:cursor-not-allowed disabled:opacity-30"
                  >
                    <span className="material-symbols-outlined text-[18px]">delete</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Creation / Edit Form Overlay Modal */}
      {isFormOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md transition-opacity duration-300">
          <div className="relative w-full max-w-lg rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-200">
            <button
              onClick={handleCloseForm}
              className="absolute top-4 right-4 inline-flex h-8 w-8 items-center justify-center rounded-full border border-outline-variant/[0.2] bg-surface-container text-on-surface hover:text-primary transition-colors"
            >
              <span className="material-symbols-outlined text-[18px]">close</span>
            </button>

            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">
                {editingUserId ? 'Modifier le compte' : 'Créer un utilisateur'}
              </h2>
              <p className="mt-1 text-xs text-on-surface-variant">
                Les comptes applicatifs restent séparés des dossiers projets clients, avec édition directe du rôle d'accès.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Login (optionnel)</label>
                <input
                  value={userForm.login}
                  onChange={(e) => setUserForm((prev) => ({ ...prev, login: e.target.value }))}
                  placeholder="login interne"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Nom Complet</label>
                <input
                  value={userForm.name}
                  onChange={(e) => setUserForm((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="Nom complet"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
              <div className="flex flex-col gap-1 sm:col-span-2">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Email</label>
                <input
                  value={userForm.email}
                  onChange={(e) => setUserForm((prev) => ({ ...prev, email: e.target.value }))}
                  placeholder="email@example.com"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
              <div className="flex flex-col gap-1 sm:col-span-2">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Mot de Passe</label>
                <input
                  type="password"
                  value={userForm.password}
                  onChange={(e) => setUserForm((prev) => ({ ...prev, password: e.target.value }))}
                  placeholder={editingUserId ? 'laisser vide pour conserver le mot de passe actuel' : 'mot de passe'}
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
              <div className="flex flex-col gap-1 sm:col-span-2">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Rôle d'Accès</label>
                <select
                  value={userForm.accessRoleId}
                  onChange={(e) => setUserForm((prev) => ({ ...prev, accessRoleId: e.target.value }))}
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                >
                  {accessRoles.map((role) => (
                    <option key={role.id} value={role.id}>{role.name}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="rounded-2xl bg-surface-container-high px-4 py-4 space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[9px] uppercase tracking-[0.2em] text-outline">Accès prévus pour le rôle</p>
                  <p className="mt-1 font-headline text-sm font-semibold text-on-surface">{selectedAccessRole?.name ?? 'Aucun rôle'}</p>
                </div>
                {selectedAccessRole && (
                  <span className="rounded-full bg-surface-container px-3 py-1 text-[9px] font-headline text-on-surface-variant font-bold">{selectedAccessRole.baseRole}</span>
                )}
              </div>
              <p className="text-xs text-on-surface-variant">{selectedAccessRole?.description || 'Ce rôle définira les permissions.'}</p>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {selectedAccessRole?.permissions.map((permission) => (
                  <span key={permission} className="rounded-full bg-surface-container px-2 py-0.5 text-[10px] text-outline border border-outline-variant/[0.1]">
                    {permissionLabelMap[permission]?.label ?? permission}
                  </span>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={handleCloseForm}
                className="rounded-2xl border border-outline-variant/[0.22] px-4 py-3 text-sm font-headline font-semibold text-on-surface hover:bg-surface-container-high transition-colors"
              >
                Annuler
              </button>
              <button
                onClick={handleSaveUser}
                className="rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary hover:bg-primary-hover transition-colors shadow-lg shadow-primary/20"
              >
                {editingUserId ? 'Enregistrer' : 'Créer'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminUsersPage;