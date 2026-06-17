import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigate, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { adminPermissionKeys } from '../constants/access';
import {
  assignEmployeeToClient,
  assignRepositoryToClient,
  createAccessRole,
  createClient,
  createUser,
  deleteAccessRole,
  deleteUser,
  getAccessRoles,
  getClients,
  getRepositories,
  getUsers,
  removeRepositoryFromClient,
  type AccessRoleDto,
  type ClientDto,
  type RepositoryDto,
  type UserDto,
  updateAccessRole,
  updateUser,
  updateUserRole,
  updateUserSuspension,
} from '../services/api';

export type UserFormState = {
  login: string;
  name: string;
  email: string;
  password: string;
  accessRoleId: string;
};

export type ClientFormState = {
  name: string;
  company: string;
  email: string;
};

export type AdminPanelContextValue = {
  users: UserDto[];
  accessRoles: AccessRoleDto[];
  clients: ClientDto[];
  repositories: RepositoryDto[];
  loading: boolean;
  message: string | null;
  error: string | null;
  userForm: UserFormState;
  clientForm: ClientFormState;
  editingUserId: number | null;
  employees: UserDto[];
  employeeSelections: Record<number, string>;
  repoSelections: Record<number, string>;
  setUserForm: React.Dispatch<React.SetStateAction<UserFormState>>;
  setClientForm: React.Dispatch<React.SetStateAction<ClientFormState>>;
  setEmployeeSelections: React.Dispatch<React.SetStateAction<Record<number, string>>>;
  setRepoSelections: React.Dispatch<React.SetStateAction<Record<number, string>>>;
  startEditingUser: (entry: UserDto) => void;
  cancelEditingUser: () => void;
  handleSaveUser: () => Promise<void>;
  handleDeleteUser: (id: number) => Promise<void>;
  handleToggleUserSuspension: (id: number, suspended: boolean) => Promise<void>;
  handleCreateClient: () => Promise<void>;
  handleRoleChange: (id: number, accessRoleId: number) => Promise<void>;
  handleSaveAccessRole: (roleId: number | null, payload: SaveRolePayload) => Promise<AccessRoleDto | null>;
  handleDeleteAccessRole: (roleId: number) => Promise<void>;
  handleAssignEmployee: (clientId: number) => Promise<void>;
  handleAssignRepository: (clientId: number) => Promise<void>;
  handleRemoveRepository: (clientId: number, repoId: number) => Promise<void>;
};

export type SaveRolePayload = {
  name: string;
  description: string;
  baseRole: string;
  permissions: string[];
};

const adminSections = [
  {
    path: '/admin/users',
    permission: 'ADMIN_USERS',
    label: 'Utilisateurs',
    icon: 'group',
    eyebrow: 'Comptes applicatifs',
    title: 'Gestion des utilisateurs',
    description: 'Créez les comptes locaux et contrôlez leurs accès sans mélanger la gestion projet dans le même écran.',
  },
  {
    path: '/admin/roles',
    permission: 'ADMIN_ROLES',
    label: 'Rôles',
    icon: 'shield_person',
    eyebrow: 'Matrice d’accès',
    title: 'Gestion des rôles',
    description: 'Visualisez les permissions par rôle et réaffectez les comptes depuis une page dédiée.',
  },
  {
    path: '/admin/projects',
    permission: 'ADMIN_PROJECTS',
    label: 'Projets',
    icon: 'apartment',
    eyebrow: 'Dossiers clients',
    title: 'Gestion des projets clients',
    description: 'Un client correspond ici à un dossier projet avec des repos liés, pas à un compte utilisateur client.',
  },
] as const;

const emptyUserForm: UserFormState = { login: '', name: '', email: '', password: '', accessRoleId: '' };
const emptyClientForm: ClientFormState = { name: '', company: '', email: '' };

const getApiErrorMessage = (err: any, fallback: string) =>
  err?.response?.data?.error || err?.response?.data?.message || fallback;

const AdminPanel: React.FC = () => {
  const location = useLocation();
  const { user, hasPermission, hasAnyPermission } = useAuth();
  const [users, setUsers] = useState<UserDto[]>([]);
  const [accessRoles, setAccessRoles] = useState<AccessRoleDto[]>([]);
  const [clients, setClients] = useState<ClientDto[]>([]);
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [userForm, setUserForm] = useState<UserFormState>(emptyUserForm);
  const [clientForm, setClientForm] = useState<ClientFormState>(emptyClientForm);
  const [editingUserId, setEditingUserId] = useState<number | null>(null);
  const [employeeSelections, setEmployeeSelections] = useState<Record<number, string>>({});
  const [repoSelections, setRepoSelections] = useState<Record<number, string>>({});

  const employees = useMemo(() => users.filter((entry) => entry.systemRole === 'EMPLOYEE' && !entry.suspended), [users]);
  const availableSections = useMemo(
    () => adminSections.filter((section) => hasPermission(section.permission)),
    [hasPermission],
  );
  const currentSection = availableSections.find((section) => location.pathname.startsWith(section.path)) ?? availableSections[0];
  const defaultEmployeeRole = useMemo(
    () => accessRoles.find((role) => role.baseRole === 'EMPLOYEE' && role.systemRole)
      ?? accessRoles.find((role) => role.baseRole === 'EMPLOYEE')
      ?? accessRoles[0]
      ?? null,
    [accessRoles],
  );

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [usersRes, accessRolesRes, clientsRes, repositoriesRes] = await Promise.all([
        getUsers(),
        getAccessRoles(),
        getClients(),
        getRepositories(),
      ]);
      setUsers(usersRes.data);
      setAccessRoles(accessRolesRes.data);
      setClients(clientsRes.data);
      setRepositories(repositoriesRes.data);
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Impossible de charger les données admin.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user?.systemRole === 'ADMIN' && hasAnyPermission(adminPermissionKeys)) {
      loadData();
    } else {
      setLoading(false);
    }
  }, [hasAnyPermission, loadData, user?.systemRole]);

  useEffect(() => {
    if (!defaultEmployeeRole) {
      return;
    }
    const currentRoleExists = accessRoles.some((role) => String(role.id) === userForm.accessRoleId);
    if (!currentRoleExists && !editingUserId) {
      setUserForm((prev) => ({ ...prev, accessRoleId: String(defaultEmployeeRole.id) }));
    }
  }, [accessRoles, defaultEmployeeRole, editingUserId, userForm.accessRoleId]);

  if (user?.systemRole !== 'ADMIN' || !hasAnyPermission(adminPermissionKeys)) {
    return (
      <div className="max-w-3xl mx-auto rounded-3xl border border-error/30 bg-error/10 p-8 text-error">
        <h1 className="font-headline text-2xl font-bold">Accès refusé</h1>
        <p className="mt-3 text-sm">Cette zone est réservée aux administrateurs.</p>
      </div>
    );
  }

  if (!currentSection) {
    return <Navigate to={availableSections[0]?.path ?? '/'} replace />;
  }

  if (!availableSections.some((section) => location.pathname.startsWith(section.path))) {
    return <Navigate to={availableSections[0].path} replace />;
  }

  const resetUserForm = () => {
    setEditingUserId(null);
    setUserForm({ ...emptyUserForm, accessRoleId: defaultEmployeeRole ? String(defaultEmployeeRole.id) : '' });
  };

  const resolveSelectedRole = () => {
    const resolvedId = userForm.accessRoleId ? Number(userForm.accessRoleId) : NaN;
    return accessRoles.find((role) => role.id === resolvedId) ?? defaultEmployeeRole;
  };

  const startEditingUser = (entry: UserDto) => {
    setEditingUserId(entry.id);
    setUserForm({
      login: entry.login ?? '',
      name: entry.name ?? '',
      email: entry.email ?? '',
      password: '',
      accessRoleId: entry.accessRoleId != null ? String(entry.accessRoleId) : '',
    });
    setMessage(null);
    setError(null);
  };

  const cancelEditingUser = () => {
    setMessage(null);
    setError(null);
    resetUserForm();
  };

  const handleSaveUser = async () => {
    if (!userForm.email.trim()) {
      setError('L\'email est obligatoire.');
      return;
    }
    if (!editingUserId && !userForm.password.trim()) {
      setError('Le mot de passe est obligatoire pour un nouveau compte.');
      return;
    }

    const selectedRole = resolveSelectedRole();
    if (!selectedRole) {
      setError('Aucun role disponible pour ce compte.');
      return;
    }

    setMessage(null);
    setError(null);
    try {
      const payload = {
        login: userForm.login.trim(),
        name: userForm.name.trim(),
        email: userForm.email.trim(),
        password: userForm.password,
        accessRoleId: selectedRole.id,
        role: selectedRole.baseRole,
      };

      if (editingUserId) {
        await updateUser(editingUserId, {
          ...payload,
          password: userForm.password.trim() ? userForm.password : undefined,
        });
        setMessage('Compte mis a jour.');
      } else {
        await createUser(payload);
        setMessage('Utilisateur cree.');
      }

      resetUserForm();
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, editingUserId ? 'Mise a jour utilisateur impossible.' : 'Creation utilisateur impossible.'));
    }
  };

  const handleCreateClient = async () => {
    if (!clientForm.name.trim()) return;
    setMessage(null);
    setError(null);
    try {
      await createClient({
        name: clientForm.name.trim(),
        company: clientForm.company.trim(),
        email: clientForm.email.trim(),
      });
      setClientForm(emptyClientForm);
      setMessage('Projet cree.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Creation projet impossible.'));
    }
  };

  const handleDeleteUser = async (id: number) => {
    setMessage(null);
    setError(null);
    try {
      await deleteUser(id);
      if (editingUserId === id) {
        resetUserForm();
      }
      setMessage('Compte supprime.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Suppression du compte impossible.'));
    }
  };

  const handleToggleUserSuspension = async (id: number, suspended: boolean) => {
    setMessage(null);
    setError(null);
    try {
      await updateUserSuspension(id, suspended);
      setMessage(suspended ? 'Compte suspendu.' : 'Compte reactive.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Mise a jour de la suspension impossible.'));
    }
  };

  const handleRoleChange = async (id: number, accessRoleId: number) => {
    setMessage(null);
    setError(null);
    try {
      const selectedRole = accessRoles.find((role) => role.id === accessRoleId);
      await updateUserRole(id, accessRoleId, selectedRole?.baseRole);
      setMessage('Role mis a jour.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Mise a jour du role impossible.'));
    }
  };

  const handleSaveAccessRole = async (roleId: number | null, payload: SaveRolePayload) => {
    if (!payload.name.trim()) {
      setError('Le nom du role est obligatoire.');
      return null;
    }
    if (!payload.permissions.length) {
      setError('Selectionnez au moins une permission.');
      return null;
    }

    setMessage(null);
    setError(null);
    try {
      const response = roleId != null
        ? await updateAccessRole(roleId, {
          name: payload.name.trim(),
          description: payload.description.trim(),
          baseRole: payload.baseRole,
          permissions: payload.permissions,
        })
        : await createAccessRole({
          name: payload.name.trim(),
          description: payload.description.trim(),
          baseRole: payload.baseRole,
          permissions: payload.permissions,
        });
      setMessage(roleId != null ? 'Role mis a jour.' : 'Role cree.');
      await loadData();
      return response.data;
    } catch (err: any) {
      setError(getApiErrorMessage(err, roleId != null ? 'Mise a jour du role impossible.' : 'Creation du role impossible.'));
      return null;
    }
  };

  const handleDeleteAccessRole = async (roleId: number) => {
    setMessage(null);
    setError(null);
    try {
      await deleteAccessRole(roleId);
      setMessage('Role supprime.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Suppression du role impossible.'));
    }
  };

  const handleAssignEmployee = async (clientId: number) => {
    const employeeId = employeeSelections[clientId];
    if (!employeeId) return;
    setMessage(null);
    setError(null);
    try {
      await assignEmployeeToClient(clientId, Number(employeeId));
      setMessage('Employe assigne au projet.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Affectation employe impossible.'));
    }
  };

  const handleAssignRepository = async (clientId: number) => {
    const repositoryId = repoSelections[clientId];
    if (!repositoryId) return;
    setMessage(null);
    setError(null);
    try {
      await assignRepositoryToClient(clientId, Number(repositoryId));
      setMessage('Depot assigne au projet.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Affectation depot impossible.'));
    }
  };

  const handleRemoveRepository = async (clientId: number, repoId: number) => {
    setMessage(null);
    setError(null);
    try {
      await removeRepositoryFromClient(clientId, repoId);
      setMessage('Depot retire du projet.');
      await loadData();
    } catch (err: any) {
      setError(getApiErrorMessage(err, 'Suppression depot impossible.'));
    }
  };

  const contextValue: AdminPanelContextValue = {
    users,
    accessRoles,
    clients,
    repositories,
    loading,
    message,
    error,
    userForm,
    clientForm,
    editingUserId,
    employees,
    employeeSelections,
    repoSelections,
    setUserForm,
    setClientForm,
    setEmployeeSelections,
    setRepoSelections,
    startEditingUser,
    cancelEditingUser,
    handleSaveUser,
    handleDeleteUser,
    handleToggleUserSuspension,
    handleCreateClient,
    handleRoleChange,
    handleSaveAccessRole,
    handleDeleteAccessRole,
    handleAssignEmployee,
    handleAssignRepository,
    handleRemoveRepository,
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <header className="space-y-2">
        <p className="text-xs uppercase tracking-[0.35em] text-outline">{currentSection.eyebrow}</p>
        <h1 className="font-headline text-3xl font-bold text-on-surface">{currentSection.title}</h1>
        <p className="text-sm text-on-surface-variant max-w-3xl">
          {currentSection.description}
        </p>
      </header>

      <div className="inline-flex max-w-full items-center gap-1 rounded-full border border-outline-variant/[0.15] bg-surface-container-low p-1 shadow-lg glass-panel overflow-x-auto">
        {availableSections.map((section) => {
          const isActive = location.pathname.startsWith(section.path);
          return (
            <NavLink
              key={section.path}
              to={section.path}
              className={`flex min-w-[170px] items-center justify-center gap-2 rounded-full px-6 py-2.5 text-sm font-headline font-semibold transition-colors duration-200 ${
                isActive
                  ? 'border border-primary/40 bg-primary/20 text-primary shadow-[0_0_12px_rgba(0,209,255,0.2)]'
                  : 'text-outline hover:text-on-surface-variant'
              }`}
            >
              <span className="material-symbols-outlined text-base">{section.icon}</span>
              <span>{section.label}</span>
            </NavLink>
          );
        })}
      </div>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error || message}
        </div>
      )}

      <Outlet context={contextValue} />
    </div>
  );
};

export default AdminPanel;