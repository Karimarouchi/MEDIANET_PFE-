import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import ScanCommitDialog from "./ScanCommitDialog";
import DeployCommitDialog from "./DeployCommitDialog";
import ProjectActivityPanel from "./ProjectActivityPanel";
import * as api from "../services/api";

jest.mock("../services/api", () => ({
  getRepoCommits: jest.fn(),
  getCommitDetail: jest.fn(),
  deployChosenCommit: jest.fn(),
  getProjectActivity: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;
const OLD = "1234567890abcdef1234567890abcdef12345678";
const commit = (sha: string, title: string): api.CommitInfo => ({
  sha, shortSha: sha.slice(0, 7), title, message: title, authorName: "Rania", authorEmail: "r@x.tn", authorLogin: "rania",
  date: "2026-10-18T10:00:00Z", url: null,
});

beforeEach(() => {
  mocked.getRepoCommits.mockResolvedValue({ data: { repositoryId: 3, repository: "k/a", branch: "main",
    commits: [commit("f".repeat(40), "dernier commit cassé"), commit(OLD, "version stable")] } } as never);
  mocked.getCommitDetail.mockResolvedValue({ data: { commit: commit(OLD, "version stable"), additions: 12, deletions: 3,
    files: [{ path: "src/App.tsx", status: "modified", additions: 12, deletions: 3 }], truncated: false } } as never);
  mocked.deployChosenCommit.mockResolvedValue({ data: {} } as never);
});

describe("ScanCommitDialog", () => {
  it("scans the latest version by default, or the chosen commit", async () => {
    const onStart = jest.fn();
    render(<ScanCommitDialog projectId={1} repositoryId={3} repoName="k/a" branch="main" onClose={() => {}} onStart={onStart} />);
    fireEvent.click(screen.getByRole("button", { name: "Lancer le scan" }));
    expect(onStart).toHaveBeenLastCalledWith(null);

    fireEvent.click(screen.getByLabelText(/Une ancienne version/));
    fireEvent.click(await screen.findByText("version stable"));
    fireEvent.click(screen.getByRole("button", { name: "Scanner 1234567" }));
    expect(onStart).toHaveBeenLastCalledWith(OLD);
  });

  it("checks a pasted short SHA and uses the full one", async () => {
    const onStart = jest.fn();
    render(<ScanCommitDialog projectId={1} repositoryId={3} repoName="k/a" onClose={() => {}} onStart={onStart} />);
    fireEvent.click(screen.getByLabelText(/Une ancienne version/));
    fireEvent.change(await screen.findByLabelText("Identifiant de commit"), { target: { value: "1234567" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    await waitFor(() => expect(mocked.getCommitDetail).toHaveBeenCalledWith(1, 3, "1234567"));
    fireEvent.click(await screen.findByRole("button", { name: "Scanner 1234567" }));
    expect(onStart).toHaveBeenCalledWith(OLD);
  });
});

describe("DeployCommitDialog", () => {
  const target = { deploymentId: 9, serverId: 2, serverName: "prod", host: "10.0.0.5", path: "/opt/app", branch: "main",
    domain: null, strategy: "DOCKER_COMPOSE", healthUrl: null, automatic: true, backupEnabled: true, backupService: "db",
    approvalRequired: false, last: null, inProduction: null, pending: null, backups: [] } as api.CdTarget;

  it("deploys the chosen commit only after its first 7 characters are typed", async () => {
    const onStarted = jest.fn();
    render(<DeployCommitDialog projectId={1} repositoryId={3} target={target} onClose={() => {}} onStarted={onStarted} />);
    fireEvent.click(await screen.findByText("version stable"));
    expect(screen.getByText(/La base est sauvegardée avant \(db\)/)).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Déployer 1234567" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Confirmation du commit"), { target: { value: "1234567" } });
    fireEvent.click(button);
    await waitFor(() => expect(onStarted).toHaveBeenCalled());
    expect(mocked.deployChosenCommit).toHaveBeenCalledWith(9, OLD);
  });
});

describe("ProjectActivityPanel", () => {
  it("shows each member's commits and their detail", async () => {
    mocked.getProjectActivity.mockResolvedValue({ data: {
      days: 30, totalCommits: 3, errors: [],
      members: [
        { userId: 1, name: "Rania", email: "r@x.tn", login: "rania", commits: 2, lastCommit: "2026-10-18T10:00:00Z", repositories: ["k/a"],
          list: [{ repositoryId: 3, repository: "k/a", sha: OLD, shortSha: "1234567", title: "version stable", authorName: "Rania",
            authorEmail: "r@x.tn", authorLogin: "rania", date: "2026-10-18T10:00:00Z", url: null }] },
        { userId: 2, name: "Melek", email: "m@x.tn", login: "melek", commits: 0, lastCommit: null, repositories: [], list: [] },
      ],
      others: [{ name: "bot", email: null, login: "dependabot", commits: 1, lastCommit: null, list: [] }],
    } } as never);
    render(<ProjectActivityPanel projectId={1} />);
    expect(await screen.findByText("2 commits")).toBeInTheDocument();
    expect(screen.getByText("0 commit")).toBeInTheDocument();
    expect(screen.getByText("Aucun commit sur la période")).toBeInTheDocument();
    expect(screen.getByText(/bot \(1\)/)).toBeInTheDocument();

    fireEvent.click(screen.getByText("Rania"));
    fireEvent.click(screen.getByText("version stable"));
    expect(await screen.findByText("src/App.tsx")).toBeInTheDocument();
    expect(mocked.getCommitDetail).toHaveBeenCalledWith(1, 3, OLD);
  });
});
