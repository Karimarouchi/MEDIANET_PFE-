import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import DeleteProjectDialog, { deletionLines } from "./DeleteProjectDialog";
import * as api from "../services/api";

jest.mock("../services/api", () => ({
  getProjectDeletionPreview: jest.fn(),
  deleteProject: jest.fn(),
}));

const preview: api.ProjectDeletionPreview = {
  projectId: 2,
  projectName: "RNIA PFE",
  repositoriesDeleted: ["karim/antigone"],
  repositoriesDetached: ["karim/commun"],
  scans: 3,
  serversDeleted: ["prod-antigone"],
  serversDetached: [],
  deployments: 1,
  ciRepositories: 1,
  blockers: [],
};

const mocked = api as jest.Mocked<typeof api>;

beforeEach(() => {
  jest.clearAllMocks();
  mocked.getProjectDeletionPreview.mockResolvedValue({ data: preview } as never);
  mocked.deleteProject.mockResolvedValue({} as never);
});

describe("deletionLines", () => {
  it("says what is deleted and what only gets detached", () => {
    const { deleted, kept } = deletionLines(preview);
    expect(deleted[0]).toBe("1 dépôt (karim/antigone) et 3 scans avec leurs vulnérabilités, secrets et fichiers de résultats");
    expect(deleted[1]).toBe("1 serveur (prod-antigone), 1 déploiement et leur historique");
    expect(deleted[2]).toContain("désactivée dans Woodpecker");
    expect(kept[0]).toBe("1 dépôt partagé avec un autre projet, seulement détaché : karim/commun");
    expect(kept[kept.length - 1]).toContain("rien n'est modifié sur les serveurs");
  });
});

describe("DeleteProjectDialog", () => {
  it("deletes only once the exact project name is typed", async () => {
    const onDeleted = jest.fn();
    render(<DeleteProjectDialog projectId={2} open onClose={() => {}} onDeleted={onDeleted} />);
    expect(await screen.findByText(/karim\/antigone/)).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Supprimer définitivement" });
    expect(button).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Nom du projet à supprimer"), { target: { value: "RNIA" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Nom du projet à supprimer"), { target: { value: "RNIA PFE" } });
    expect(button).toBeEnabled();

    fireEvent.click(button);
    await waitFor(() => expect(onDeleted).toHaveBeenCalled());
    expect(mocked.deleteProject).toHaveBeenCalledWith(2, "RNIA PFE");
  });

  it("stays off while a scan or a deployment is running", async () => {
    mocked.getProjectDeletionPreview.mockResolvedValue({
      data: { ...preview, blockers: ["Un scan est en cours sur karim/antigone : attendez la fin ou arrêtez-le."] },
    } as never);
    render(<DeleteProjectDialog projectId={2} open onClose={() => {}} onDeleted={() => {}} />);
    expect(await screen.findByText(/Un scan est en cours/)).toBeInTheDocument();
    expect(screen.getByLabelText("Nom du projet à supprimer")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Supprimer définitivement" })).toBeDisabled();
  });

  it("shows the server's reason when the deletion fails", async () => {
    mocked.deleteProject.mockRejectedValue({ response: { data: { message: "Le nom saisi ne correspond pas au nom du projet." } } });
    const onDeleted = jest.fn();
    render(<DeleteProjectDialog projectId={2} open onClose={() => {}} onDeleted={onDeleted} />);
    fireEvent.change(await screen.findByLabelText("Nom du projet à supprimer"), { target: { value: "RNIA PFE" } });
    fireEvent.click(screen.getByRole("button", { name: "Supprimer définitivement" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("ne correspond pas");
    expect(onDeleted).not.toHaveBeenCalled();
  });
});
