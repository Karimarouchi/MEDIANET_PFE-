import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import RemoveProjectRepoDialog from "./RemoveProjectRepoDialog";
import * as api from "../services/api";

jest.mock("../services/api", () => ({
  getRepoRemovalPreview: jest.fn(),
  removeRepositoryFromClient: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;
const base: api.RepoRemovalPreview = {
  repositoryId: 5, repository: "karim/antigone", shared: false, canDelete: true, scans: 2, ciEnabled: true, blockers: [],
};

beforeEach(() => {
  mocked.getRepoRemovalPreview.mockResolvedValue({ data: base } as never);
  mocked.removeRepositoryFromClient.mockResolvedValue({} as never);
});

describe("RemoveProjectRepoDialog", () => {
  it("detaches by default and says the CI goes off", async () => {
    const onRemoved = jest.fn();
    render(<RemoveProjectRepoDialog projectId={1} repositoryId={5} onClose={() => {}} onRemoved={onRemoved} />);
    expect(await screen.findByText(/Sa CI, activée par ce projet, sera désactivée/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retirer du projet" }));
    await waitFor(() => expect(onRemoved).toHaveBeenCalled());
    expect(mocked.removeRepositoryFromClient).toHaveBeenCalledWith(1, 5, false);
  });

  it("deletes the repository and its scans only when ticked", async () => {
    render(<RemoveProjectRepoDialog projectId={1} repositoryId={5} onClose={() => {}} onRemoved={() => {}} />);
    fireEvent.click(await screen.findByLabelText(/Supprimer aussi le dépôt et ses 2 scan/));
    fireEvent.click(screen.getByRole("button", { name: "Retirer et supprimer" }));
    await waitFor(() => expect(mocked.removeRepositoryFromClient).toHaveBeenCalledWith(1, 5, true));
  });

  it("offers no deletion for a repository shared with another project", async () => {
    mocked.getRepoRemovalPreview.mockResolvedValue({ data: { ...base, shared: true, canDelete: false } } as never);
    render(<RemoveProjectRepoDialog projectId={1} repositoryId={5} onClose={() => {}} onRemoved={() => {}} />);
    expect(await screen.findByText(/aussi utilisé par un autre projet/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Supprimer aussi/)).toBeNull();
  });
});
