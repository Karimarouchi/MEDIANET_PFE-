import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import axios from "axios";
import {
  defaultPermissionsBySystemRole,
  hasAnyPermission as checkAnyPermission,
  hasPermission as checkPermission,
} from "../constants/access";

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

/** Decode a JWT payload without verifying the signature (client-side only). */
function decodeJwtPayload(token: string): any | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** Return true if the token's exp claim is in the future (or missing). */
function isTokenExpired(claims: any): boolean {
  if (!claims?.exp) return false;
  return Date.now() / 1000 > claims.exp;
}

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
  };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<AppUser | null>(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    localStorage.removeItem("vulnix_token");
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const token = localStorage.getItem("vulnix_token");
    if (!token) {
      setUser(null);
      return;
    }
    try {
      const res = await axios.get("/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      });

      const nextUser = buildUserFromPayload(res.data ?? {});
      if (nextUser.suspended) {
        logout();
        return;
      }
      setUser(nextUser);
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 401 || status === 403 || status === 423) {
        logout();
      }
      throw err;
    }
  }, [logout]);

  useEffect(() => {
    const token = localStorage.getItem("vulnix_token");
    if (!token) {
      setLoading(false);
      return;
    }

    // Decode the JWT locally — no backend call needed.
    const claims = decodeJwtPayload(token);
    if (!claims || isTokenExpired(claims)) {
      // Token is malformed or expired: clear it.
      localStorage.removeItem("vulnix_token");
      setLoading(false);
      return;
    }

    const nextUser = buildUserFromPayload(claims);
    if (nextUser.suspended) {
      localStorage.removeItem("vulnix_token");
      setLoading(false);
      return;
    }

    // Restore the session immediately from the token claims.
    setUser(nextUser);
    setLoading(false);

    // Optionally refresh user data from the backend in the background.
    // We do NOT remove the token if this call fails (backend may be starting up).
    refreshUser().catch(() => {
      /* keep the locally-decoded session */
    });
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
