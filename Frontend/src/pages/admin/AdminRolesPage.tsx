import React, { useEffect, useMemo, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { defaultPermissionsBySystemRole, permissionCatalog } from '../../constants/access';
import { type AccessRoleDto } from '../../services/api';
import { type AdminPanelContextValue, type SaveRolePayload } from '../AdminPanel';
import ConfirmModal from '../../components/ConfirmModal';

type RoleFormState = SaveRolePayload;

const createEmptyRoleForm = (baseRole: 'ADMIN' | 'EMPLOYEE' = 'EMPLOYEE'): RoleFormState => ({
  name: '',
  description: '',
  baseRole,
  permissions: [...defaultPermissionsBySystemRole[baseRole]],
});

const buildRoleForm = (role: AccessRoleDto): RoleFormState => ({
  name: role.name,
  description: role.description ?? '',
  baseRole: role.baseRole === 'ADMIN' ? 'ADMIN' : 'EMPLOYEE',
  permissions: role.permissions,
});

const AdminRolesPage: React.FC = () => {
  const { users, accessRoles, loading, handleRoleChange, handleSaveAccessRole, handleDeleteAccessRole } = useOutletContext<AdminPanelContextValue>();
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(null);
  const [isCreatingRole, setIsCreatingRole] = useState(false);
  const [roleForm, setRoleForm] = useState<RoleFormState>(() => createEmptyRoleForm());
  const [deleteModal, setDeleteModal] = useState<{ open: boolean; role: AccessRoleDto | null }>({ open: false, role: null });
  const [isFormOpen, setIsFormOpen] = useState(false);

  const roleCounts = useMemo(() => {
    return users.reduce<Record<number, number>>((acc, entry) => {
      if (entry.accessRoleId != null) {
        acc[entry.accessRoleId] = (acc[entry.accessRoleId] ?? 0) + 1;
      }
      return acc;
    }, {});
  }, [users]);

  const selectedRole = useMemo(
    () => accessRoles.find((entry) => entry.id === selectedRoleId) ?? null,
    [accessRoles, selectedRoleId],
  );

  const permissionGroups = useMemo(
    () => ({
      Core: permissionCatalog.filter((entry) => entry.section === 'Core'),
      Administration: permissionCatalog.filter((entry) => entry.section === 'Administration'),
    }),
    [],
  );

  useEffect(() => {
    if (!accessRoles.length) {
      setSelectedRoleId(null);
      return;
    }
    if (isCreatingRole) {
      return;
    }
    if (selectedRoleId == null || !accessRoles.some((entry) => entry.id === selectedRoleId)) {
      const fallbackRole = accessRoles[0];
      setSelectedRoleId(fallbackRole.id);
      setRoleForm(buildRoleForm(fallbackRole));
    }
  }, [accessRoles, isCreatingRole, selectedRoleId]);

  useEffect(() => {
    if (!isCreatingRole && selectedRole) {
      setRoleForm(buildRoleForm(selectedRole));
    }
  }, [isCreatingRole, selectedRole]);

  const selectRole = (role: AccessRoleDto) => {
    setIsCreatingRole(false);
    setSelectedRoleId(role.id);
    setRoleForm(buildRoleForm(role));
    setIsFormOpen(true);
  };

  const startNewRole = () => {
    setIsCreatingRole(true);
    setSelectedRoleId(null);
    setRoleForm(createEmptyRoleForm());
    setIsFormOpen(true);
  };

  const handleCloseForm = () => {
    setIsFormOpen(false);
    setIsCreatingRole(false);
    if (accessRoles.length > 0 && selectedRoleId === null) {
      setSelectedRoleId(accessRoles[0].id);
    }
  };

  const togglePermission = (permission: string) => {
    setRoleForm((prev) => {
      const exists = prev.permissions.includes(permission);
      return {
        ...prev,
        permissions: exists ? prev.permissions.filter((entry) => entry !== permission) : [...prev.permissions, permission],
      };
    });
  };

  const handleBaseRoleChange = (baseRole: 'ADMIN' | 'EMPLOYEE') => {
    setRoleForm((prev) => {
      const nextPermissions = baseRole === 'ADMIN'
        ? Array.from(new Set([...prev.permissions, ...defaultPermissionsBySystemRole.ADMIN]))
        : prev.permissions.filter((permission) => !permission.startsWith('ADMIN_'));
      return {
        ...prev,
        baseRole,
        permissions: nextPermissions.length ? nextPermissions : [...defaultPermissionsBySystemRole[baseRole]],
      };
    });
  };

  const submitRole = async () => {
    const savedRole = await handleSaveAccessRole(isCreatingRole ? null : selectedRoleId, roleForm);
    if (savedRole) {
      setIsFormOpen(false);
      setIsCreatingRole(false);
      setSelectedRoleId(savedRole.id);
      setRoleForm(buildRoleForm(savedRole));
    }
  };

  const confirmDeleteRole = (role: AccessRoleDto) => {
    if (role.systemRole) return;
    setDeleteModal({ open: true, role });
  };

  return (
    <div className="space-y-8">
      <ConfirmModal
        open={deleteModal.open}
        title="Supprimer le rôle"
        message={`Supprimer le rôle ${deleteModal.role?.name} ? Cette action est définitive.`}
        confirmLabel="Supprimer"
        danger
        onConfirm={async () => { const r = deleteModal.role; setDeleteModal({ open: false, role: null }); if (r) await handleDeleteAccessRole(r.id); }}
        onCancel={() => setDeleteModal({ open: false, role: null })}
      />

      {/* Header and Nouveau role button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-outline-variant/[0.12] pb-6">
        <div>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Matrice des Rôles</h2>
          <p className="mt-1 text-sm text-on-surface-variant">Configurez les privilèges, créez de nouveaux profils d'accès et gérez la matrice de permissions.</p>
        </div>
        <button
          onClick={startNewRole}
          className="inline-flex items-center justify-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-bold text-on-primary hover:bg-primary-hover transition-colors shadow-lg shadow-primary/20 self-start sm:self-auto"
        >
          <span className="material-symbols-outlined text-[18px]">add_moderator</span>
          <span>Nouveau rôle</span>
        </button>
      </div>

      {/* Roles Cards Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {accessRoles.map((role) => {
          const isSystem = role.systemRole;
          const count = roleCounts[role.id] ?? 0;
          return (
            <div
              key={role.id}
              className="relative flex flex-col justify-between rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4 hover:border-outline-variant/60 transition-all duration-300 hover:shadow-xl group"
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="font-headline text-base font-bold text-on-surface group-hover:text-primary transition-colors">
                    {role.name}
                  </h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="rounded-full bg-surface-container-high border border-outline-variant/[0.15] px-2 py-0.5 text-[9px] font-headline font-bold uppercase tracking-wider text-on-surface-variant">
                      {role.baseRole}
                    </span>
                    {isSystem && (
                      <span className="rounded-full bg-primary/10 border border-primary/20 px-2 py-0.5 text-[9px] font-headline font-bold uppercase tracking-wider text-primary">
                        Système
                      </span>
                    )}
                  </div>
                </div>
                <span className="text-[10px] font-semibold text-outline shrink-0">
                  {role.permissions.length} modules
                </span>
              </div>

              {/* Description */}
              <p className="text-xs text-on-surface-variant line-clamp-2 leading-relaxed">
                {role.description || 'Rôle personnalisé sans description.'}
              </p>

              {/* Accounts count info */}
              <div className="text-[11px] text-outline flex items-center gap-1.5 bg-surface-container-high/40 rounded-xl px-3 py-2 border border-outline-variant/[0.08]">
                <span className="material-symbols-outlined text-[15px]">people</span>
                <span><strong>{count}</strong> {count > 1 ? 'comptes affectés' : 'compte affecté'}</span>
              </div>

              {/* Actions footer */}
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-outline-variant/[0.08]">
                <button
                  type="button"
                  title="Modifier les permissions"
                  onClick={() => selectRole(role)}
                  className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-on-surface transition-colors hover:border-primary/40 hover:text-primary hover:bg-surface-container"
                >
                  <span className="material-symbols-outlined text-[18px]">edit_note</span>
                </button>
                {!isSystem && (
                  <button
                    type="button"
                    title="Supprimer le rôle"
                    onClick={() => confirmDeleteRole(role)}
                    className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-on-surface transition-colors hover:border-error/40 hover:text-error hover:bg-surface-container"
                  >
                    <span className="material-symbols-outlined text-[18px]">delete</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Role Reassignment section */}
      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div>
          <h2 className="font-headline text-xl font-semibold text-on-surface">Réaffecter les Rôles Comptes</h2>
          <p className="mt-1 text-sm text-on-surface-variant">Changez le rôle d'un compte directement depuis cette matrice d'accès.</p>
        </div>
        
        {loading ? (
          <div className="flex items-center justify-center py-6">
            <span className="animate-spin inline-block h-6 w-6 rounded-full border-2 border-primary border-t-transparent" />
            <p className="ml-3 text-xs text-outline">Chargement des comptes…</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 max-h-[30rem] overflow-y-auto pr-1">
            {users.map((entry) => (
              <div key={entry.id} className="rounded-2xl border border-outline-variant/[0.12] bg-surface-container-high p-4 flex flex-col justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <p className="font-headline text-sm font-semibold text-on-surface">{entry.name || entry.login}</p>
                    {entry.suspended && (
                      <span className="rounded-full bg-error/10 border border-error/20 px-2 py-0.5 text-[9px] font-headline font-bold text-error">Suspendu</span>
                    )}
                  </div>
                  <p className="text-xs text-outline truncate">{entry.email || 'Email non renseigné'}</p>
                </div>
                <div className="flex items-center justify-between gap-2 border-t border-outline-variant/[0.08] pt-2 mt-1">
                  <span className="text-[11px] text-on-surface-variant font-medium">Rôle : <strong className="text-primary font-semibold">{entry.role}</strong></span>
                  <select
                    value={entry.accessRoleId ?? ''}
                    onChange={(e) => e.target.value && handleRoleChange(entry.id, Number(e.target.value))}
                    className="rounded-xl border border-outline-variant/[0.2] bg-surface-container px-2.5 py-1.5 text-xs text-on-surface outline-none focus:border-primary transition-colors"
                  >
                    {accessRoles.map((role) => (
                      <option key={role.id} value={role.id}>{role.name}</option>
                    ))}
                  </select>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Creation / Edit Form Overlay Modal */}
      {isFormOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md transition-opacity duration-300">
          <div className="relative w-full max-w-4xl rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-200">
            <button
              onClick={handleCloseForm}
              className="absolute top-4 right-4 inline-flex h-8 w-8 items-center justify-center rounded-full border border-outline-variant/[0.2] bg-surface-container text-on-surface hover:text-primary transition-colors"
            >
              <span className="material-symbols-outlined text-[18px]">close</span>
            </button>

            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">
                {isCreatingRole ? 'Ajouter un rôle' : `Fiche rôle : ${selectedRole?.name ?? ''}`}
              </h2>
              <p className="mt-1 text-xs text-on-surface-variant">
                Choisissez la base ADMIN ou EMPLOYEE, puis activez les permissions visibles dans l'application.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Nom du rôle</label>
                <input
                  value={roleForm.name}
                  onChange={(event) => setRoleForm((prev) => ({ ...prev, name: event.target.value }))}
                  placeholder="Nom du rôle"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Rôle de Base</label>
                <select
                  value={roleForm.baseRole}
                  disabled={Boolean(selectedRole?.systemRole)}
                  onChange={(event) => handleBaseRoleChange(event.target.value === 'ADMIN' ? 'ADMIN' : 'EMPLOYEE')}
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary disabled:cursor-not-allowed disabled:opacity-60 transition-colors"
                >
                  <option value="EMPLOYEE">EMPLOYEE</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
              </div>
              <div className="flex flex-col gap-1 sm:col-span-2">
                <label className="text-[10px] uppercase tracking-wider text-outline px-1">Description</label>
                <textarea
                  value={roleForm.description}
                  onChange={(event) => setRoleForm((prev) => ({ ...prev, description: event.target.value }))}
                  rows={2}
                  placeholder="Description du rôle"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none focus:border-primary transition-colors"
                />
              </div>
            </div>

            {/* Scrollable Permissions Box */}
            <div className="space-y-4 max-h-[22rem] overflow-y-auto pr-2 bg-surface-container-low border border-outline-variant/[0.08] rounded-2xl p-4">
              {Object.entries(permissionGroups).map(([section, entries]) => (
                <div key={section} className="space-y-3">
                  <p className="text-[10px] uppercase tracking-[0.25em] text-outline font-bold border-b border-outline-variant/[0.08] pb-1">{section}</p>
                  <div className="grid gap-3 sm:grid-cols-2">
                    {entries.map((permission) => {
                      const isAdminPermission = permission.key.startsWith('ADMIN_');
                      const disabled = roleForm.baseRole !== 'ADMIN' && isAdminPermission;
                      const checked = roleForm.permissions.includes(permission.key);
                      return (
                        <label
                          key={permission.key}
                          className={`flex items-start gap-3 rounded-2xl border px-4 py-3.5 transition-colors ${
                            checked
                              ? 'border-primary/40 bg-primary/10'
                              : 'border-outline-variant/[0.16] bg-surface-container-high'
                          } ${disabled ? 'opacity-60' : 'cursor-pointer hover:border-primary/25'}`}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={disabled}
                            onChange={() => togglePermission(permission.key)}
                            className="mt-1 h-4 w-4 rounded border-outline-variant/[0.3] text-primary focus:ring-primary/25"
                          />
                          <div>
                            <p className="text-sm font-headline font-semibold text-on-surface">{permission.label}</p>
                            <p className="mt-1 text-xs text-on-surface-variant leading-relaxed">{permission.description}</p>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={handleCloseForm}
                className="rounded-2xl border border-outline-variant/[0.22] px-4 py-3 text-sm font-headline font-semibold text-on-surface hover:bg-surface-container-high transition-colors"
              >
                Annuler
              </button>
              <button
                onClick={submitRole}
                className="rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary hover:bg-primary-hover transition-colors shadow-lg shadow-primary/20"
              >
                {isCreatingRole ? 'Créer' : 'Enregistrer'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminRolesPage;