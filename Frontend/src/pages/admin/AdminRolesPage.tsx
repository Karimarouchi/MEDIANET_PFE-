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
  };

  const startNewRole = () => {
    setIsCreatingRole(true);
    setSelectedRoleId(null);
    setRoleForm(createEmptyRoleForm());
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
      selectRole(savedRole);
    }
  };

  const confirmDeleteRole = (role: AccessRoleDto) => {
    if (role.systemRole) return;
    setDeleteModal({ open: true, role });
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <ConfirmModal
        open={deleteModal.open}
        title="Supprimer le rôle"
        message={`Supprimer le rôle ${deleteModal.role?.name} ? Cette action est définitive.`}
        confirmLabel="Supprimer"
        danger
        onConfirm={async () => { const r = deleteModal.role; setDeleteModal({ open: false, role: null }); if (r) await handleDeleteAccessRole(r.id); }}
        onCancel={() => setDeleteModal({ open: false, role: null })}
      />
      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="font-headline text-xl font-semibold text-on-surface">Matrice d'acces</h2>
            <p className="mt-2 text-sm text-on-surface-variant">Chaque role est maintenant dynamique, avec creation, edition de permissions et suppression si le role n'est pas systeme.</p>
          </div>
          <button onClick={startNewRole} className="rounded-2xl bg-primary px-4 py-3 text-sm font-headline font-semibold text-on-primary">
            Nouveau role
          </button>
        </div>

        <div className="grid gap-3">
          {accessRoles.map((role) => (
            <button
              key={role.id}
              type="button"
              onClick={() => selectRole(role)}
              className={`rounded-2xl border px-4 py-4 text-left transition-colors ${selectedRoleId === role.id && !isCreatingRole ? 'border-primary/40 bg-primary/10' : 'border-outline-variant/[0.16] bg-surface-container-high hover:border-primary/25'}`}
            >
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-headline text-sm font-semibold text-on-surface">{role.name}</p>
                    <span className="rounded-full bg-surface-container px-3 py-1 text-[10px] uppercase tracking-[0.2em] text-on-surface">{role.baseRole}</span>
                    {role.systemRole && (
                      <span className="rounded-full bg-primary/12 px-3 py-1 text-[10px] uppercase tracking-[0.2em] text-primary">Systeme</span>
                    )}
                  </div>
                  <p className="text-xs text-outline mt-1">{role.description || 'Role personnalise sans description.'}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase tracking-[0.25em] text-outline">{role.permissions.length} modules</span>
                  {!role.systemRole && (
                    <span
                      onClick={(event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        void confirmDeleteRole(role);
                      }}
                      className="material-symbols-outlined rounded-full border border-outline-variant/[0.2] p-2 text-[18px] text-outline transition-colors hover:border-error/40 hover:text-error"
                    >
                      delete
                    </span>
                  )}
                </div>
              </div>
              <p className="mt-3 text-sm text-on-surface-variant">{roleCounts[role.id] ?? 0} comptes affectes</p>
            </button>
          ))}
        </div>
      </section>

      <div className="space-y-6">
        <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">{isCreatingRole ? 'Ajouter un role' : `Fiche role: ${selectedRole?.name ?? ''}`}</h2>
              <p className="mt-2 text-sm text-on-surface-variant">Choisissez la base ADMIN ou EMPLOYEE, puis activez les permissions visibles dans l'application.</p>
            </div>
            {!isCreatingRole && selectedRole && (
              <span className="rounded-full bg-surface-container-high px-3 py-1 text-[11px] font-headline text-on-surface">{roleCounts[selectedRole.id] ?? 0} comptes</span>
            )}
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <input
              value={roleForm.name}
              onChange={(event) => setRoleForm((prev) => ({ ...prev, name: event.target.value }))}
              placeholder="Nom du role"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm"
            />
            <select
              value={roleForm.baseRole}
              disabled={Boolean(selectedRole?.systemRole)}
              onChange={(event) => handleBaseRoleChange(event.target.value === 'ADMIN' ? 'ADMIN' : 'EMPLOYEE')}
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm disabled:cursor-not-allowed disabled:opacity-60"
            >
              <option value="EMPLOYEE">EMPLOYEE</option>
              <option value="ADMIN">ADMIN</option>
            </select>
            <textarea
              value={roleForm.description}
              onChange={(event) => setRoleForm((prev) => ({ ...prev, description: event.target.value }))}
              rows={3}
              placeholder="Description du role"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm sm:col-span-2"
            />
          </div>

          <div className="space-y-4">
            {Object.entries(permissionGroups).map(([section, entries]) => (
              <div key={section} className="space-y-3">
                <p className="text-[11px] uppercase tracking-[0.25em] text-outline">{section}</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {entries.map((permission) => {
                    const isAdminPermission = permission.key.startsWith('ADMIN_');
                    const disabled = roleForm.baseRole !== 'ADMIN' && isAdminPermission;
                    const checked = roleForm.permissions.includes(permission.key);
                    return (
                      <label key={permission.key} className={`flex items-start gap-3 rounded-2xl border px-4 py-4 transition-colors ${checked ? 'border-primary/40 bg-primary/10' : 'border-outline-variant/[0.16] bg-surface-container-high'} ${disabled ? 'opacity-60' : 'cursor-pointer'}`}>
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={disabled}
                          onChange={() => togglePermission(permission.key)}
                          className="mt-1 h-4 w-4 rounded border-outline-variant/[0.3]"
                        />
                        <div>
                          <p className="text-sm font-headline font-semibold text-on-surface">{permission.label}</p>
                          <p className="mt-1 text-xs text-on-surface-variant">{permission.description}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-3">
            <button onClick={submitRole} className="rounded-2xl bg-primary px-4 py-3 text-sm font-headline font-semibold text-on-primary">
              {isCreatingRole ? 'Creer le role' : 'Enregistrer le role'}
            </button>
            {(isCreatingRole || selectedRole) && (
              <button onClick={() => selectedRole ? selectRole(selectedRole) : startNewRole()} className="rounded-2xl border border-outline-variant/[0.22] px-4 py-3 text-sm font-headline font-semibold text-on-surface">
                Reinitialiser
              </button>
            )}
          </div>
        </section>

        <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">Reaffecter les roles</h2>
              <p className="mt-2 text-sm text-on-surface-variant">Changez le role d'un compte sans quitter la page roles.</p>
            </div>
            <span className="text-xs text-outline">{users.length} comptes</span>
          </div>

          {loading ? (
            <p className="text-sm text-outline">Chargement…</p>
          ) : (
            <div className="space-y-3 max-h-[28rem] overflow-y-auto pr-2">
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
                    <p className="text-xs text-outline">{entry.email || 'Email non renseigne'} · {entry.systemRole}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[11px] text-outline">Role actuel: {entry.role}</span>
                    <select value={entry.accessRoleId ?? ''} onChange={(e) => e.target.value && handleRoleChange(entry.id, Number(e.target.value))} className="rounded-xl border border-outline-variant/[0.2] bg-surface-container px-3 py-2 text-sm">
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
      </div>
    </div>
  );
};

export default AdminRolesPage;