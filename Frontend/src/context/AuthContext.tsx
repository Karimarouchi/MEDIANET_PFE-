import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import {
  defaultPermissionsBySystemRole,
  hasAnyPermission as checkAnyPermission,
  hasPermission as checkPermission,
} from "../constants/access";
import { apiUrl } from "../services/api";
import axios from "axios";

export interface AppUser {
  id: string;
  login: string;
  name: string;
  avatarUrl: string;
  email: string;
  role: string;
  systemRole: "ADMIN" | "EMPLOYEE";
  accessRoleId?: number | null;
  accessRoleKey?: string | null;
  permissions: string[];
  suspended: boolean;
  primaryProvider: "GITHUB" | "GITLAB" | "LOCAL" | string;
  hasGithubLinked: boolean;
  hasGitlabLinked: boolean;
  gitlabUrl?: string | null;
  hasLocalPassword: boolean;
  createdAt?: string;
  aiProvider?: string | null;
  aiModel?: string | null;
  hasCustomAiKey?: boolean;
  hasCustomChatAiKey?: boolean;
  chatAiProvider?: string | null;
  chatAiModel?: string | null;
}

interface AuthContextType {
  user: AppUser | null;
  loading: boolean;
  refreshUser: () => Promise<void>;
  logout: () => void;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  refreshUser: async () => {},
  logout: () => {},
  hasPermission: () => false,
  hasAnyPermission: () => false,
});

export const useAuth = () => useContext(AuthContext);

function normalizeSystemRole(rawRole: unknown): "ADMIN" | "EMPLOYEE" {
  return String(rawRole ?? "").toUpperCase() === "ADMIN" ? "ADMIN" : "EMPLOYEE";
}

function normalizePermissions(
  rawPermissions: unknown,
  systemRole: "ADMIN" | "EMPLOYEE",
): string[] {
  if (Array.isArray(rawPermissions)) {
    const normalized = rawPermissions
      .map((entry) => String(entry ?? "").toUpperCase())
      .filter(Boolean);
    if (normalized.length) {
      return Array.from(new Set(normalized));
    }
  }
  return [...defaultPermissionsBySystemRole[systemRole]];
}

function buildUserFromPayload(payload: any): AppUser {
  const systemRole = normalizeSystemRole(payload.systemRole ?? payload.role);
  return {
    id: String(payload.id ?? payload.sub ?? ""),
    login: String(payload.login ?? ""),
    name: String(payload.name ?? payload.login ?? ""),
    avatarUrl: String(payload.avatarUrl ?? payload.avatar ?? ""),
    email: String(payload.email ?? ""),
    role: String(payload.roleName ?? payload.role ?? ""),
    systemRole,
    accessRoleId:
      payload.accessRoleId != null ? Number(payload.accessRoleId) : undefined,
    accessRoleKey:
      payload.accessRoleKey != null ? String(payload.accessRoleKey) : undefined,
    permissions: normalizePermissions(payload.permissions, systemRole),
    suspended: Boolean(payload.suspended),
    primaryProvider: String(
      payload.primaryProvider ?? payload.provider ?? "LOCAL",
    ),
    hasGithubLinked: Boolean(
      payload.hasGithubLinked ??
        String(
          payload.primaryProvider ?? payload.provider ?? "",
        ).toUpperCase() === "GITHUB",
    ),
    hasGitlabLinked: Boolean(
      payload.hasGitlabLinked ??
        String(
          payload.primaryProvider ?? payload.provider ?? "",
        ).toUpperCase() === "GITLAB",
    ),
    gitlabUrl: payload.gitlabUrl ?? null,
    hasLocalPassword: Boolean(payload.hasLocalPassword),
    createdAt: payload.createdAt ? String(payload.createdAt) : undefined,
    aiProvider: payload.aiProvider ?? null,
    aiModel: payload.aiModel ?? null,
    hasCustomAiKey: Boolean(payload.hasCustomAiKey),
    hasCustomChatAiKey: Boolean(payload.hasCustomChatAiKey),
    chatAiProvider: payload.chatAiProvider ?? null,
    chatAiModel: payload.chatAiModel ?? null,
  };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<AppUser | null>(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    // Clear legacy token if present from older sessions.
    localStorage.removeItem("vulnix_token");
    setUser(null);
    axios
      .post(apiUrl("/api/auth/logout"), null, { withCredentials: true })
      .catch(() => {
        /* ignore network errors on logout */
      });
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const res = await axios.get(apiUrl("/api/auth/me"), {
        withCredentials: true,
      });

      const nextUser = buildUserFromPayload(res.data ?? {});
      if (nextUser.suspended) {
        logout();
        return;
      }
      setUser(nextUser);
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 401) {
        try {
          await axios.post(apiUrl("/api/auth/refresh"), null, {
            withCredentials: true,
          });
          const retry = await axios.get(apiUrl("/api/auth/me"), {
            withCredentials: true,
          });
          const nextUser = buildUserFromPayload(retry.data ?? {});
          if (nextUser.suspended) {
            logout();
            return;
          }
          setUser(nextUser);
          return;
        } catch {
          logout();
          return;
        }
      }
      if (status === 403 || status === 423) {
        logout();
      }
      throw err;
    }
  }, [logout]);

  useEffect(() => {
    refreshUser()
      .catch(() => {
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, [refreshUser]);

  const hasPermission = useCallback(
    (permission: string) => checkPermission(user?.permissions, permission),
    [user?.permissions],
  );
  const hasAnyPermission = useCallback(
    (permissions: string[]) =>
      checkAnyPermission(user?.permissions, permissions),
    [user?.permissions],
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        refreshUser,
        logout,
        hasPermission,
        hasAnyPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
