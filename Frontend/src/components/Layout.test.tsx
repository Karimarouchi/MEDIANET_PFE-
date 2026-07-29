/**
 * Tests unitaires pour le composant Layout.
 * Virtualise react-router-dom pour compatibilité Jest v27 / React Router v7.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";

// Mock virtualisé de react-router-dom
jest.mock(
  "react-router-dom",
  () => ({
    NavLink: ({ children, to, className }: any) => {
      const cls = typeof className === "function" ? className({ isActive: false }) : className;
      return <a href={to} className={cls}>{children}</a>;
    },
    Outlet: () => <div data-testid="outlet-content">Page Content</div>,
    useLocation: () => ({ pathname: "/" }),
  }),
  { virtual: true }
);

// Mock du contexte Auth
const mockUseAuth = jest.fn();
jest.mock("../context/AuthContext", () => ({
  useAuth: () => mockUseAuth(),
}));

import Layout from "./Layout";

// ──────────────────────────────────────────────────────────────────────────────
// Helper : rendu du Layout comme ADMIN
// ──────────────────────────────────────────────────────────────────────────────
const renderLayoutAsAdmin = () => {
  mockUseAuth.mockReturnValue({
    user: {
      id: "1",
      login: "admin",
      name: "Admin Test",
      avatarUrl: "",
      email: "admin@test.com",
      role: "ADMIN",
      systemRole: "ADMIN",
      permissions: [
        "DASHBOARD", "REPOSITORIES", "SCANS", "VULNERABILITIES",
        "SSL_ANALYSIS", "SERVER_CONFIG", "CVE_JOURNAL", "PROFILE",
        "ADMIN_USERS", "ADMIN_ROLES", "ADMIN_PROJECTS", "PROJECTS",
      ],
      suspended: false,
      primaryProvider: "LOCAL",
      hasGithubLinked: false,
      hasGitlabLinked: false,
      hasLocalPassword: true,
    },
    logout: jest.fn(),
    hasPermission: () => true,
    hasAnyPermission: () => true,
    refreshUser: jest.fn(),
    loading: false,
  });

  return render(<Layout />);
};

const renderLayoutAsEmployee = () => {
  mockUseAuth.mockReturnValue({
    user: {
      id: "2",
      login: "emp1",
      name: "Employé Test",
      avatarUrl: "",
      email: "emp@test.com",
      role: "EMPLOYEE",
      systemRole: "EMPLOYEE",
      permissions: ["DASHBOARD", "SCANS"],
      suspended: false,
      primaryProvider: "LOCAL",
      hasGithubLinked: false,
      hasGitlabLinked: false,
      hasLocalPassword: true,
    },
    logout: jest.fn(),
    hasPermission: (perm: string) => ["DASHBOARD", "SCANS"].includes(perm),
    hasAnyPermission: () => false,
    refreshUser: jest.fn(),
    loading: false,
  });

  return render(<Layout />);
};

// ──────────────────────────────────────────────────────────────────────────────
// Tests de rendu du menu
// ──────────────────────────────────────────────────────────────────────────────

describe("Layout — rendu du menu de navigation", () => {
  test("affiche le nom de l'application dans la barre latérale", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Tactical OS")).toBeInTheDocument();
  });

  test("affiche le lien Dashboard quand l'utilisateur a la permission DASHBOARD", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
  });

  test("affiche le lien Scans quand l'utilisateur a la permission SCANS", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Scans")).toBeInTheDocument();
  });

  test("affiche le lien SSL Analysis quand l'utilisateur a la permission SSL_ANALYSIS", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("SSL Analysis")).toBeInTheDocument();
  });

  test("affiche le lien Server Config quand l'utilisateur a la permission SERVER_CONFIG", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Server Config")).toBeInTheDocument();
  });

  test("affiche le lien Journal CVE quand l'utilisateur a la permission CVE_JOURNAL", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Journal CVE")).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Tests de filtrage selon les permissions
// ──────────────────────────────────────────────────────────────────────────────

describe("Layout — filtrage selon les permissions", () => {
  test("EMPLOYEE sans permission SSL_ANALYSIS ne voit pas le lien SSL Analysis", () => {
    renderLayoutAsEmployee();
    expect(screen.queryByText("SSL Analysis")).not.toBeInTheDocument();
  });

  test("EMPLOYEE sans permission SERVER_CONFIG ne voit pas le lien Server Config", () => {
    renderLayoutAsEmployee();
    expect(screen.queryByText("Server Config")).not.toBeInTheDocument();
  });

  test("EMPLOYEE sans permissions admin ne voit pas le panneau admin", () => {
    renderLayoutAsEmployee();
    expect(screen.queryByText("Admin Panel")).not.toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Tests du contenu (Outlet)
// ──────────────────────────────────────────────────────────────────────────────

describe("Layout — rendu du contenu (Outlet)", () => {
  test("rend le slot Outlet pour afficher le contenu de la page", () => {
    renderLayoutAsAdmin();
    expect(screen.getByTestId("outlet-content")).toBeInTheDocument();
  });

  test("affiche le contenu de la page enfant via Outlet", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("Page Content")).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Tests du profil utilisateur
// ──────────────────────────────────────────────────────────────────────────────

describe("Layout — profil utilisateur", () => {
  test("affiche le login de l'utilisateur connecté", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  test("affiche le rôle et provider de l'utilisateur", () => {
    renderLayoutAsAdmin();
    expect(screen.getByText(/ADMIN/)).toBeInTheDocument();
  });
});
