import React from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { adminPermissionKeys } from "../constants/access";

const Layout: React.FC = () => {
  const location = useLocation();
  const { user, logout, hasPermission, hasAnyPermission } = useAuth();
  const navItems = [
    {
      path: "/",
      label: "Dashboard",
      icon: "dashboard",
      permission: "DASHBOARD",
    },
    {
      path: "/repositories",
      label: "Repositories",
      icon: "code_blocks",
      permission: "REPOSITORIES",
    },
    {
      path: "/projects",
      label: "Projects",
      icon: "folder_special",
      permission: "PROJECTS",
    },
    { path: "/scans", label: "Scans", icon: "radar", permission: "SCANS" },
    {
      path: "/ssl-analysis",
      label: "SSL Analysis",
      icon: "verified_user",
      permission: "SSL_ANALYSIS",
    },
    {
      path: "/server-config",
      label: "Server Config",
      icon: "terminal",
      permission: "SERVER_CONFIG",
    },
    {
      path: "/pipeline",
      label: "Pipeline",
      icon: "settings_ethernet",
      permission: "PIPELINE",
    },
  ].filter((item) => hasPermission(item.permission));

  const showAdmin =
    hasAnyPermission(adminPermissionKeys) && user?.systemRole === "ADMIN";

  const isProfileActive = location.pathname === "/profile";

  return (
    <div className="dark bg-surface-container-lowest text-on-surface font-body min-h-screen">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-screen w-64 border-r border-outline-variant/[0.15] bg-surface-container-low hidden md:flex flex-col py-6 z-50">
        <div className="px-6 mb-10 flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-primary to-secondary rounded-lg flex items-center justify-center">
            <span
              className="material-symbols-outlined text-on-primary text-xl"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              shield
            </span>
          </div>
          <div>
            <h2 className="font-headline font-bold text-on-surface text-base tracking-tight leading-none">
              Tactical OS
            </h2>
            <p className="text-[10px] text-outline uppercase tracking-widest mt-1">
              Quantum Observer v1.0
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 px-4">
          {navItems.map((item) => {
            const isActive =
              item.path === "/"
                ? location.pathname === "/"
                : location.pathname === item.path ||
                  location.pathname.startsWith(`${item.path}/`);
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 font-headline text-sm font-medium transition-colors duration-200 ${
                  isActive
                    ? "text-primary bg-surface-container border-l-2 border-primary"
                    : "text-slate-500 hover:bg-surface-container hover:text-primary"
                }`}
              >
                <span className="material-symbols-outlined">{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="px-4 mt-auto border-t border-outline-variant/[0.1] pt-4 space-y-1">
          {showAdmin && (
            <NavLink
              to="/admin"
              className={`flex items-center gap-3 px-4 py-2.5 font-headline text-sm font-medium w-full rounded-lg transition-colors duration-200 ${
                location.pathname === "/admin"
                  ? "text-primary bg-surface-container border-l-2 border-primary"
                  : "text-slate-500 hover:bg-surface-container hover:text-primary"
              }`}
            >
              <span className="material-symbols-outlined text-base">
                admin_panel_settings
              </span>
              <span>Admin</span>
            </NavLink>
          )}
          <NavLink
            to="/profile"
            className={`flex items-center gap-3 px-4 py-2.5 font-headline text-sm font-medium w-full rounded-lg transition-colors duration-200 ${
              isProfileActive
                ? "text-primary bg-surface-container border-l-2 border-primary"
                : "text-slate-500 hover:bg-surface-container hover:text-primary"
            }`}
          >
            <span className="material-symbols-outlined text-base">
              account_circle
            </span>
            <span>Profile</span>
          </NavLink>

          {/* User account */}
          {user ? (
            <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-surface-container mt-1">
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.login}
                  className="w-8 h-8 rounded-full border border-outline-variant/[0.3] object-cover flex-shrink-0"
                />
              ) : (
                <div className="w-8 h-8 rounded-full bg-surface-container-high border border-outline-variant/[0.3] flex items-center justify-center flex-shrink-0">
                  <span className="material-symbols-outlined text-primary text-base">
                    person
                  </span>
                </div>
              )}
              <div className="flex-1 min-w-0">
                <p className="text-xs font-headline font-semibold text-on-surface truncate">
                  {user.login}
                </p>
                <p className="text-[10px] text-outline truncate">
                  {user.role} · {user.primaryProvider}
                </p>
              </div>
              <button
                onClick={logout}
                title="Déconnexion"
                className="text-slate-500 hover:text-error transition-colors flex-shrink-0"
              >
                <span className="material-symbols-outlined text-base">
                  logout
                </span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-surface-container mt-1">
              <div className="w-8 h-8 rounded-full bg-surface-container-high border border-outline-variant/[0.3] flex items-center justify-center flex-shrink-0">
                <span className="material-symbols-outlined text-primary text-base">
                  person
                </span>
              </div>
              <p className="text-xs text-outline font-headline">Non connecté</p>
            </div>
          )}
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="md:ml-64 h-screen overflow-y-auto bg-surface-container-lowest">
        {/* Page Content */}
        <div className="pt-8 px-8 pb-12">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

export default Layout;
