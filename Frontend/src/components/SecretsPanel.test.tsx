import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import SecretsPanel from "./SecretsPanel";
import { effectiveVerdict, groupSecrets, secretPriority } from "../utils/secretView";
import type { SecretDto } from "../services/api";

const secret = (id: number, over: Partial<SecretDto> = {}): SecretDto => ({
  id,
  ruleId: "generic-api-key",
  description: "",
  file: `/workspace/repo/src/f${id}.js`,
  startLine: 1,
  endLine: 1,
  author: "",
  date: "",
  commit: "",
  maskedMatch: "abcd...wxyz",
  ...over,
});

describe("secretView", () => {
  test("the analyst's call overrides the model", () => {
    expect(effectiveVerdict(secret(1, { mlVerdict: "LIKELY_FALSE_POSITIVE", analystVerdict: "REAL" }))).toBe("LIKELY_REAL");
    expect(effectiveVerdict(secret(1, { mlVerdict: "LIKELY_REAL", analystVerdict: "FALSE_POSITIVE" }))).toBe(
      "LIKELY_FALSE_POSITIVE",
    );
    expect(effectiveVerdict(secret(1))).toBe("UNTRIAGED");
  });

  test("priority: confirmed > production real > test real > to check > false positive", () => {
    const order = [
      secretPriority(secret(1, { analystVerdict: "REAL" })),
      secretPriority(secret(2, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION" })),
      secretPriority(secret(3, { mlVerdict: "LIKELY_REAL", mlScope: "TEST_OR_DOC" })),
      secretPriority(secret(4, { mlVerdict: "REVIEW" })),
      secretPriority(secret(5, { mlVerdict: "LIKELY_FALSE_POSITIVE" })),
    ];
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(new Set(order).size).toBe(5);
  });

  test("groups: real first by probability, untriaged never hidden", () => {
    const g = groupSecrets([
      secret(1, { mlVerdict: "LIKELY_FALSE_POSITIVE", mlProba: 0.02 }),
      secret(2, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.8 }),
      secret(3, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.97 }),
      secret(4),
    ]);
    expect(g.toHandle.map((s) => s.id)).toEqual([3, 2]);
    expect(g.toCheck.map((s) => s.id)).toEqual([4]);
    expect(g.falsePositives.map((s) => s.id)).toEqual([1]);
    expect(g.untriaged).toBe(1);
  });

  test("real-looking values in test/doc files go to their own low-priority group, unless the analyst says real", () => {
    const g = groupSecrets([
      secret(1, { mlVerdict: "LIKELY_REAL", mlScope: "TEST_OR_DOC", mlProba: 0.99 }),
      secret(2, { mlVerdict: "LIKELY_REAL", mlScope: "TEST_OR_DOC", mlProba: 0.99, analystVerdict: "REAL" }),
      secret(3, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.9 }),
    ]);
    expect(g.testAndDocs.map((s) => s.id)).toEqual([1]);
    expect(g.toHandle.map((s) => s.id)).toEqual([2, 3]);
  });
});

describe("SecretsPanel", () => {
  const triaged = [
    secret(1, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.97, mlReasons: ["valeur très aléatoire"] }),
    secret(2, { mlVerdict: "LIKELY_FALSE_POSITIVE", mlProba: 0.02, ruleId: "faux-un" }),
  ];

  test("probable false positives are hidden until asked", () => {
    render(<SecretsPanel secrets={triaged} loading={false} onTriage={() => {}} onVerdict={() => {}} />);
    expect(screen.getByText(/À traiter en premier/)).toBeTruthy();
    expect(screen.queryByText("faux-un")).toBeNull();
    fireEvent.click(screen.getByText(/Voir les 1 faux positif/));
    expect(screen.getByText("faux-un")).toBeTruthy();
  });

  test("a row shows the reasons and lets the analyst decide", () => {
    const onVerdict = jest.fn();
    render(<SecretsPanel secrets={triaged} loading={false} onTriage={() => {}} onVerdict={onVerdict} />);
    fireEvent.click(screen.getByText("generic-api-key"));
    expect(screen.getByText("valeur très aléatoire")).toBeTruthy();
    fireEvent.click(screen.getByText("C'est un faux positif"));
    expect(onVerdict).toHaveBeenCalledWith(1, "FALSE_POSITIVE");
  });

  test("untriaged secrets are shown with a button to run the model", () => {
    const onTriage = jest.fn();
    render(<SecretsPanel secrets={[secret(7)]} loading={false} onTriage={onTriage} onVerdict={() => {}} />);
    expect(screen.getByText("Non trié")).toBeTruthy();
    fireEvent.click(screen.getByText(/Trier avec le modèle \(1\)/));
    expect(onTriage).toHaveBeenCalled();
  });

  test("empty and all-false-positive states", () => {
    const { rerender } = render(<SecretsPanel secrets={[]} loading={false} onTriage={() => {}} onVerdict={() => {}} />);
    expect(screen.getByText("Aucun secret détecté")).toBeTruthy();
    rerender(
      <SecretsPanel
        secrets={[secret(2, { mlVerdict: "LIKELY_FALSE_POSITIVE", mlProba: 0.02 })]}
        loading={false}
        onTriage={() => {}}
        onVerdict={() => {}}
      />,
    );
    expect(screen.getByText(/probablement des faux positifs/)).toBeTruthy();
  });

  test("shows when two detectors agree, and which one found a secret alone", () => {
    render(
      <SecretsPanel
        secrets={[
          secret(1, { mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.9, detectors: ["gitleaks", "credsweeper"] }),
          secret(2, { ruleId: "credsweeper:Password", mlVerdict: "LIKELY_REAL", mlScope: "PRODUCTION", mlProba: 0.8, detectors: ["credsweeper"] }),
        ]}
        loading={false}
        onTriage={() => {}}
        onVerdict={() => {}}
      />,
    );
    expect(screen.getByText("2 détecteurs")).toBeTruthy();
    expect(screen.getByText("CredSweeper")).toBeTruthy();
    expect(screen.getByText(/Password/)).toBeTruthy(); // "credsweeper:" prefix is not shown
  });
});
