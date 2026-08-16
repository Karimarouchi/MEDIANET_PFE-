/**
 * Tests unitaires pour services/api.ts
 * Utilise axios-mock-adapter sur l'instance API exportée.
 *
 * Si un test échoue → le nom du test indique quelle fonction API est cassée.
 */
import MockAdapter from "axios-mock-adapter";

import API, {
  getClients,
  getClient,
  createClient,
  updateClient,
  startScan,
  getAllScans,
  getCvesByScan,
  getRepositories,
  getUsers,
  getServerNodes,
  loginWithEmail,
  deleteUser,
  updateUserSuspension,
  getAccessRoles,
  getCveJournal,
  stopScan,
  deleteScan,
  listCiTokens,
  createCiToken,
  revokeCiToken,
} from "./api";

let mock: MockAdapter;

beforeEach(() => {
  mock = new MockAdapter(API);
  localStorage.clear();
});

afterEach(() => {
  mock.restore();
});

// ──────────────────────────────────────────────────────────────────────────────
// Clients
// ──────────────────────────────────────────────────────────────────────────────

describe("getClients — GET /clients", () => {
  test("retourne la liste des clients avec succès", async () => {
    const fakeClients = [
      { id: 1, name: "Client A", employeeIds: [], repositoryIds: [], employeeLogins: [], repositoryUrls: [] },
      { id: 2, name: "Client B", employeeIds: [], repositoryIds: [], employeeLogins: [], repositoryUrls: [] },
    ];
    mock.onGet("/clients").reply(200, fakeClients);

    const response = await getClients();
    expect(response.data).toHaveLength(2);
    expect(response.data[0].name).toBe("Client A");
  });

  test("lève une erreur si le serveur retourne 401", async () => {
    mock.onGet("/clients").reply(401);
    await expect(getClients()).rejects.toThrow();
  });
});

describe("getClient — GET /clients/:id", () => {
  test("retourne un client par son id", async () => {
    const fakeClient = { id: 5, name: "VIP Client", employeeIds: [], repositoryIds: [], employeeLogins: [], repositoryUrls: [] };
    mock.onGet("/clients/5").reply(200, fakeClient);

    const response = await getClient(5);
    expect(response.data.name).toBe("VIP Client");
    expect(response.data.id).toBe(5);
  });

  test("lève une erreur si le client n'existe pas (404)", async () => {
    mock.onGet("/clients/999").reply(404);
    await expect(getClient(999)).rejects.toThrow();
  });
});

describe("createClient — POST /clients", () => {
  test("envoie le bon payload et retourne le client créé", async () => {
    const payload = { name: "Nouveau Client", company: "Acme", email: "contact@acme.com" };
    const created = { id: 10, ...payload, employeeIds: [], repositoryIds: [], employeeLogins: [], repositoryUrls: [] };
    mock.onPost("/clients").reply(200, created);

    const response = await createClient(payload);
    expect(response.data.id).toBe(10);
    expect(response.data.name).toBe("Nouveau Client");
  });
});

describe("updateClient — PUT /clients/:id", () => {
  test("met à jour un client et retourne les nouvelles données", async () => {
    const payload = { name: "Nom Modifié", company: "NewCo", email: "new@newco.com" };
    const updated = { id: 5, ...payload, employeeIds: [], repositoryIds: [], employeeLogins: [], repositoryUrls: [] };
    mock.onPut("/clients/5").reply(200, updated);

    const response = await updateClient(5, payload);
    expect(response.data.name).toBe("Nom Modifié");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Scans
// ──────────────────────────────────────────────────────────────────────────────

describe("startScan — POST /scans", () => {
  test("envoie une requête de démarrage de scan", async () => {
    const payload = { repoUrl: "https://github.com/user/repo", branch: "main" };
    const result = { scanId: 42, repoId: 7 };
    mock.onPost("/scans").reply(200, result);

    const response = await startScan(payload);
    expect(response.data.scanId).toBe(42);
    expect(response.data.repoId).toBe(7);
  });
});

describe("getAllScans — GET /scans", () => {
  test("retourne la liste de tous les scans", async () => {
    const scans = [
      { id: 1, repoUrl: "https://github.com/test/repo", status: "COMPLETED", cveCount: 5, secretCount: 0 },
    ];
    mock.onGet("/scans").reply(200, scans);

    const response = await getAllScans();
    expect(response.data).toHaveLength(1);
    expect(response.data[0].status).toBe("COMPLETED");
  });
});

describe("getCvesByScan — GET /scans/:id/cves", () => {
  test("retourne les CVEs pour un scan donné", async () => {
    const cves = [
      { id: 1, cveId: "CVE-2023-1234", severity: "HIGH", packageName: "axios", cvssScore: 8.5 },
    ];
    mock.onGet("/scans/1/cves").reply(200, cves);

    const response = await getCvesByScan(1);
    expect(response.data[0].cveId).toBe("CVE-2023-1234");
    expect(response.data[0].severity).toBe("HIGH");
  });
});

describe("stopScan — POST /scans/:id/stop", () => {
  test("envoie la demande d'arrêt du scan", async () => {
    mock.onPost("/scans/3/stop").reply(200, {});
    const response = await stopScan(3);
    expect(response.status).toBe(200);
  });
});

describe("deleteScan — DELETE /scans/:id", () => {
  test("supprime un scan par son id", async () => {
    mock.onDelete("/scans/7").reply(200, {});
    const response = await deleteScan(7);
    expect(response.status).toBe(200);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Repositories
// ──────────────────────────────────────────────────────────────────────────────

describe("getRepositories — GET /repositories", () => {
  test("retourne la liste des repositories", async () => {
    const repos = [
      { id: 1, repoUrl: "https://github.com/user/repo", branch: "main", scanMode: "FULL" },
    ];
    mock.onGet("/repositories").reply(200, repos);

    const response = await getRepositories();
    expect(response.data).toHaveLength(1);
    expect(response.data[0].repoUrl).toContain("github.com");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Utilisateurs
// ──────────────────────────────────────────────────────────────────────────────

describe("getUsers — GET /users", () => {
  test("retourne la liste des utilisateurs", async () => {
    const users = [
      { id: 1, login: "admin", role: "ADMIN", suspended: false, permissions: [] },
      { id: 2, login: "emp1", role: "EMPLOYEE", suspended: false, permissions: [] },
    ];
    mock.onGet("/users").reply(200, users);

    const response = await getUsers();
    expect(response.data).toHaveLength(2);
    expect(response.data[0].login).toBe("admin");
  });
});

describe("deleteUser — DELETE /users/:id", () => {
  test("supprime un utilisateur par son id", async () => {
    mock.onDelete("/users/2").reply(200, {});
    const response = await deleteUser(2);
    expect(response.status).toBe(200);
  });
});

describe("updateUserSuspension — PUT /users/:id/suspension", () => {
  test("suspend un utilisateur", async () => {
    const updated = { id: 2, login: "emp1", suspended: true };
    mock.onPut("/users/2/suspension").reply(200, updated);

    const response = await updateUserSuspension(2, true);
    expect(response.data.suspended).toBe(true);
  });

  test("réactive un compte suspendu", async () => {
    const updated = { id: 2, login: "emp1", suspended: false };
    mock.onPut("/users/2/suspension").reply(200, updated);

    const response = await updateUserSuspension(2, false);
    expect(response.data.suspended).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Serveurs
// ──────────────────────────────────────────────────────────────────────────────

describe("getServerNodes — GET /servers", () => {
  test("retourne la liste des noeuds serveur", async () => {
    const servers = [
      { id: 1, name: "Prod Server", host: "10.0.0.1", port: 22, username: "ubuntu",
        nodeType: "LINUX", criticalCount: 0, warningCount: 2, infoCount: 5, tags: [] },
    ];
    mock.onGet("/servers").reply(200, servers);

    const response = await getServerNodes();
    expect(response.data).toHaveLength(1);
    expect(response.data[0].host).toBe("10.0.0.1");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────────────────────────────────

describe("loginWithEmail — POST /auth/login", () => {
  test("retourne l'utilisateur en cas de succès (session via cookies HttpOnly)", async () => {
    const result = {
      user: { id: 1, login: "Admin@Medianet.com", role: "ADMIN" },
    };
    mock.onPost("/auth/login").reply(200, result);

    const response = await loginWithEmail("Admin@Medianet.com", "Password@123");
    expect(response.data.user.login).toBe("Admin@Medianet.com");
  });

  test("lève une erreur 401 pour des identifiants invalides", async () => {
    mock.onPost("/auth/login").reply(401, { message: "Invalid credentials" });
    await expect(loginWithEmail("wrong@mail.com", "wrongpass")).rejects.toThrow();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Rôles d'accès
// ──────────────────────────────────────────────────────────────────────────────

describe("getAccessRoles — GET /access-roles", () => {
  test("retourne la liste des rôles d'accès", async () => {
    const roles = [
      { id: 1, roleKey: "ADMIN", name: "Admin", baseRole: "ADMIN", systemRole: true, permissions: [] },
      { id: 2, roleKey: "EMPLOYEE", name: "Employee", baseRole: "EMPLOYEE", systemRole: true, permissions: [] },
    ];
    mock.onGet("/access-roles").reply(200, roles);

    const response = await getAccessRoles();
    expect(response.data).toHaveLength(2);
    expect(response.data[0].roleKey).toBe("ADMIN");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Journal CVE
// ──────────────────────────────────────────────────────────────────────────────

describe("getCveJournal — GET /cve-journal", () => {
  test("retourne le catalogue CVE", async () => {
    const payload = {
      catalog: [{ cveId: "CVE-2025-48988", packageName: "tomcat", severity: "HIGH" }],
      interventions: [],
      stats: { totalCves: 1, withOfficialGuidance: 0, withDeveloperFix: 0, interventionCount: 0 },
    };
    mock.onGet("/cve-journal").reply(200, payload);

    const response = await getCveJournal();
    expect(response.data.catalog).toHaveLength(1);
    expect(response.data.catalog[0].cveId).toBe("CVE-2025-48988");
  });
});

describe("listCiTokens — GET /admin/ci-tokens", () => {
  test("envoie le clientId et retourne les jetons sans secret", async () => {
    mock.onGet("/admin/ci-tokens", { params: { clientId: 12 } }).reply(200, [
      { id: 1, name: "GitHub Actions", tokenPrefix: "vx_live_abcd", clientId: 12, repositoryIds: [7], active: true },
    ]);

    const response = await listCiTokens(12);
    expect(response.data).toHaveLength(1);
    expect(response.data[0].tokenPrefix).toBe("vx_live_abcd");
    expect(response.data[0]).not.toHaveProperty("token");
  });
});

describe("createCiToken — POST /admin/ci-tokens", () => {
  test("envoie le payload scoped et récupère le plaintext une fois", async () => {
    mock.onPost("/admin/ci-tokens").reply(200, {
      id: 1,
      name: "GitHub Actions",
      token: "vx_live_secret",
      tokenPrefix: "vx_live_secr",
      clientId: 12,
      repositoryIds: [7],
      active: true,
    });

    const response = await createCiToken({
      name: "GitHub Actions",
      clientId: 12,
      repositoryIds: [7],
      expiresInDays: 90,
    });
    expect(response.data.token).toBe("vx_live_secret");
  });
});

describe("revokeCiToken — DELETE /admin/ci-tokens/:id", () => {
  test("révoque le jeton", async () => {
    mock.onDelete("/admin/ci-tokens/5").reply(200, { id: 5, active: false, revokedAt: "2026-08-16T00:00:00Z" });
    const response = await revokeCiToken(5);
    expect(response.data.active).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Intercepteur JWT — vérifie que le token est attaché aux requêtes
// ──────────────────────────────────────────────────────────────────────────────

describe("Client API — cookies de session", () => {
  test("envoie les requêtes avec withCredentials (cookies HttpOnly)", async () => {
    let capturedWithCredentials: boolean | undefined;
    mock.onGet("/clients").reply((config) => {
      capturedWithCredentials = config.withCredentials;
      return [200, []];
    });

    await getClients();

    expect(capturedWithCredentials).toBe(true);
  });
});
