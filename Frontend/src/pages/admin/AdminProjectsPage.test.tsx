import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import AdminProjectsPage from "./AdminProjectsPage";
import { getServerNodes } from "../../services/api";

jest.mock("../../services/api", () => ({
  getServerNodes: jest.fn(() => Promise.resolve({ data: [] })),
}));

// Virtual router (Jest 27 cannot load React Router v7), as in Layout.test.tsx.
const mockNavigate = jest.fn();
let mockContext: unknown = null;
jest.mock(
  "react-router-dom",
  () => ({
    Link: ({ children, to }: any) => <a href={to}>{children}</a>,
    useNavigate: () => mockNavigate,
    useOutletContext: () => mockContext,
    useSearchParams: () => [new URLSearchParams(), jest.fn()],
  }),
  { virtual: true },
);

function renderPage(handleCreateClient: jest.Mock) {
  mockContext = {
    clients: [], repositories: [], loading: false,
    clientForm: { name: "Antigone", company: "", domainName: "", email: "", releaseDeadline: "2026-12-01", releaseLabel: "" },
    setClientForm: jest.fn(), employees: [], employeeSelections: {}, repoSelections: {},
    setEmployeeSelections: jest.fn(), setRepoSelections: jest.fn(), handleCreateClient,
    handleAssignEmployee: jest.fn(), handleAssignRepository: jest.fn(), handleRemoveRepository: jest.fn(),
    handleSetDeadline: jest.fn(), message: null, error: null,
  };
  render(<AdminProjectsPage />);
}

const openRepoStep = () => {
  fireEvent.click(screen.getAllByRole("button", { name: /Créer un projet/ })[0]);
  fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
};

beforeEach(() => {
  mockNavigate.mockReset();
  (getServerNodes as jest.Mock).mockResolvedValue({ data: [] });
});

describe("AdminProjectsPage — création d'un projet", () => {
  it("keeps a URL typed without pressing « Ajouter » and opens the project with the warnings", async () => {
    const create = jest.fn().mockResolvedValue({ id: 7, warnings: ["Dépôt x : refusé"] });
    renderPage(create);
    openRepoStep();
    fireEvent.change(screen.getByPlaceholderText("github.com/organisation/depot"), {
      target: { value: "github.com/Karimarouchi/Antigone_finance" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    fireEvent.click(await screen.findByRole("button", { name: /Créer le projet/ }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0][0].newRepoUrls).toEqual(["https://github.com/Karimarouchi/Antigone_finance"]);
    expect(mockNavigate).toHaveBeenCalledWith("/projects/7", { state: { creationWarnings: ["Dépôt x : refusé"] } });
  });

  it("refuses to go on with text that is not a repository address", () => {
    renderPage(jest.fn());
    openRepoStep();
    fireEvent.change(screen.getByPlaceholderText("github.com/organisation/depot"), { target: { value: "antigone" } });
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Ce n'est pas une adresse de dépôt");
    expect(screen.getByPlaceholderText("github.com/organisation/depot")).toBeInTheDocument();
  });

  it("keeps a server typed without pressing « Ajouter ce serveur »", async () => {
    const create = jest.fn().mockResolvedValue({ id: 8, warnings: [] });
    renderPage(create);
    openRepoStep();
    fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
    fireEvent.change(await screen.findByPlaceholderText("IP ou domaine"), { target: { value: "10.0.0.5" } });
    fireEvent.click(screen.getByRole("button", { name: /Créer le projet/ }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(create.mock.calls[0][0].newServers).toEqual([{ name: "Front", host: "10.0.0.5", environment: "TEST" }]);
  });
});
