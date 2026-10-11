import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import ModelsPage, { statusOf } from "./ModelsPage";
import * as api from "../services/api";

const card = (over: Partial<api.ModelCard>): api.ModelCard => ({
  id: "m", name: "Modèle test", status: "RELIABLE", version: "v1", kind: "ML", purpose: "Sert à tester.", usedIn: "Partout.",
  how: "Par magie.", dataset: { name: "Jeu", size: "100 lignes", split: "par dépôt" },
  metrics: [{ label: "Rappel", value: "97 %", note: "validation" }], limits: ["Limite A"], sources: ["ml/x.json"], removed: false,
  live: { tracked: true, installed: true, exportedAt: "2026-10-06" }, ...over,
});

afterEach(() => jest.restoreAllMocks());

test("each status has a label and the removed one is marked as such", () => {
  expect(statusOf({ status: "RELIABLE" }).label).toBe("Fiable");
  expect(statusOf({ status: "REMOVED" }).label).toBe("Retiré");
  expect(statusOf({ status: "???" }).label).toBe("À améliorer"); // unknown never shows as reliable
});

test("shows version, measured figures and the limits of every model", async () => {
  jest.spyOn(api, "getModelCards").mockResolvedValue({
    data: { updated: "2026-10-11", models: [card({}), card({ id: "r", name: "Ancien", status: "REMOVED", removed: true, metrics: [], live: { tracked: false, installed: false } })] },
  } as any);
  render(<ModelsPage />);
  await waitFor(() => expect(screen.getByText("Modèle test")).toBeTruthy());
  expect(screen.getByText("97 %")).toBeTruthy();
  expect(screen.getAllByText("Limite A").length).toBeGreaterThan(0);
  expect(screen.getByText("Fiable")).toBeTruthy();
  expect(screen.getByText("Retiré")).toBeTruthy();
  expect(screen.getByText("Actif sur ce serveur")).toBeTruthy();
  expect(screen.getAllByText("Limites à connaître")).toHaveLength(2); // limits are never hidden
});

test("a model missing from the server is flagged, details are folded until asked", async () => {
  jest.spyOn(api, "getModelCards").mockResolvedValue({ data: { models: [card({ live: { tracked: true, installed: false } })] } } as any);
  render(<ModelsPage />);
  await waitFor(() => expect(screen.getByText("Absent de ce serveur")).toBeTruthy());
  expect(screen.queryByText("Par magie.")).toBeNull();
  fireEvent.click(screen.getByText(/Voir comment il décide/));
  expect(screen.getByText("Par magie.")).toBeTruthy();
  expect(screen.getByText("ml/x.json")).toBeTruthy();
});

test("a refused or failed request says so", async () => {
  jest.spyOn(api, "getModelCards").mockRejectedValue(new Error("403"));
  render(<ModelsPage />);
  await waitFor(() => expect(screen.getByText(/Impossible de charger/)).toBeTruthy());
});
