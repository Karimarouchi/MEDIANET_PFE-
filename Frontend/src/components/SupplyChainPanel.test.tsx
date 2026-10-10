import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import SupplyChainPanel, {
  SupplyChainCell,
  SupplyChainSummary,
  ecosystemOfPurl,
  formatProba,
  supplyChainKey,
  tierBadge,
  useSupplyChainReport,
} from "./SupplyChainPanel";
import * as api from "../services/api";

jest.mock("../services/api", () => ({
  getSupplyChain: jest.fn(),
  analyzeSupplyChain: jest.fn(),
  checkSupplyChain: jest.fn(),
}));

const base: api.SupplyChainReport = {
  scanId: 7,
  enabled: true,
  modelAvailable: true,
  modelVersion: "v4",
  analysisRunning: false,
  totalComponents: 5,
  summary: { knownMalicious: 1, highConfidence: 1, review: 0, low: 3, notAnalysed: 0, pending: 0 },
  flagged: [
    {
      name: "evil-pkg",
      version: "1.0.0",
      tier: "KNOWN_MALICIOUS",
      suspicionProba: 1,
      reasons: ["Listé comme malveillant par OSSF malicious-packages"],
      knownMaliciousId: "MAL-2022-2",
    },
    {
      name: "shady",
      version: "2.3.4",
      tier: "HIGH_CONFIDENCE",
      suspicionProba: 0.93,
      probableType: "credential_stealer",
      reasons: ["Le code lit des secrets et fait une requête réseau"],
    },
  ],
  disclaimer: "Indicateur statistique ... pas une décision de blocage.",
};

const mockGet = api.getSupplyChain as jest.Mock;
const mockAnalyze = api.analyzeSupplyChain as jest.Mock;
const mockCheck = api.checkSupplyChain as jest.Mock;

describe("SupplyChainPanel", () => {
  beforeEach(() => jest.clearAllMocks());

  it("affiche les paquets signalés, leur niveau, leur type et la raison", async () => {
    mockGet.mockResolvedValue({ data: base });
    render(<SupplyChainPanel scanId={7} />);
    expect(await screen.findByText("Connu malveillant")).toBeInTheDocument();
    expect(screen.getByText("Confiance élevée", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText(/Voleur d'informations/)).toBeInTheDocument();
    expect(screen.getByText(/lit des secrets/)).toBeInTheDocument();
    expect(screen.getByText(/pas une décision de blocage/)).toBeInTheDocument();
  });

  it("affiche un message rassurant quand rien n'est suspect", async () => {
    mockGet.mockResolvedValue({
      data: { ...base, flagged: [], summary: { ...base.summary, knownMalicious: 0, highConfidence: 0, low: 5 } },
    });
    render(<SupplyChainPanel scanId={7} />);
    expect(await screen.findByText(/Aucun paquet suspect parmi les 5/)).toBeInTheDocument();
  });

  it("propose d'analyser les dépendances en attente et rafraîchit le rapport", async () => {
    mockGet.mockResolvedValue({
      data: { ...base, flagged: [], summary: { ...base.summary, knownMalicious: 0, highConfidence: 0, low: 0, pending: 5 } },
    });
    mockAnalyze.mockResolvedValue({ data: base });
    render(<SupplyChainPanel scanId={7} />);
    const button = await screen.findByRole("button", { name: /Analyser \(5 à faire\)/ });
    fireEvent.click(button);
    await waitFor(() => expect(mockAnalyze).toHaveBeenCalledWith(7));
    expect(await screen.findByText("Connu malveillant")).toBeInTheDocument();
  });

  it("indique quand le SBOM ne contient aucune dépendance npm", async () => {
    mockGet.mockResolvedValue({
      data: { ...base, totalComponents: 0, flagged: [], summary: { ...base.summary, knownMalicious: 0, highConfidence: 0, low: 0 } },
    });
    render(<SupplyChainPanel scanId={7} />);
    expect(await screen.findByText(/Aucune dépendance npm ou PyPI/)).toBeInTheDocument();
  });

  it("prévient quand le modèle n'est pas installé sur le serveur", async () => {
    mockGet.mockResolvedValue({ data: { ...base, modelAvailable: false } });
    render(<SupplyChainPanel scanId={7} />);
    expect(await screen.findByText(/n'est pas installé sur ce serveur/)).toBeInTheDocument();
  });
});

describe("liste des dépendances analysées", () => {
  const withList: api.SupplyChainReport = {
    ...base,
    flagged: [],
    summary: { ...base.summary, knownMalicious: 0, highConfidence: 0, review: 0, low: 2, notAnalysed: 1 },
    analyzed: [
      { ecosystem: "npm", name: "nodemailer", version: "10.0.10", status: "SCORED", tier: "LOW", suspicionProba: 0.078 },
      { ecosystem: "npm", name: "lodash", version: "4.17.21", status: "SCORED", tier: "LOW", suspicionProba: 0.0001 },
    ],
    skipped: [{ ecosystem: "npm", name: "sm-travelle", version: "1.0.0", status: "NOT_FOUND", tier: null }],
  };

  it("est repliée par défaut puis montre chaque dépendance avec son score", async () => {
    mockGet.mockResolvedValue({ data: withList });
    render(<SupplyChainPanel scanId={7} />);
    const toggle = await screen.findByRole("button", { name: /Voir les 2 dépendances analysées/ });
    expect(screen.queryByText("nodemailer")).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.getByText("nodemailer")).toBeInTheDocument();
    expect(screen.getByText("8 %")).toBeInTheDocument();   // nodemailer: 0.078
    expect(screen.getByText("0.0 %")).toBeInTheDocument(); // lodash: 0.0001
    expect(screen.getAllByText("Sans alerte").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/introuvable sur le registre public/)).toBeInTheDocument();
  });
});

describe("Tester un paquet", () => {
  beforeEach(() => {
    mockGet.mockResolvedValue({ data: { ...base, flagged: [] } });
  });

  it("envoie le paquet saisi et affiche le niveau et les raisons", async () => {
    mockCheck.mockResolvedValue({
      data: [
        {
          name: "wfetch",
          version: "1.0.0",
          ecosystem: "npm",
          status: "SCORED",
          tier: "HIGH_CONFIDENCE",
          suspicionProba: 0.91,
          probableType: "credential_stealer",
          reasons: ["Le script d'installation contacte un serveur inconnu"],
        },
      ],
    });
    render(<SupplyChainPanel scanId={7} />);
    fireEvent.change(await screen.findByLabelText("Nom du paquet"), { target: { value: "wfetch" } });
    fireEvent.change(screen.getByLabelText("Version"), { target: { value: "1.0.0" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    await waitFor(() =>
      expect(mockCheck).toHaveBeenCalledWith([{ ecosystem: "npm", name: "wfetch", version: "1.0.0" }])
    );
    const card = await screen.findByTestId("check-result");
    expect(card).toHaveTextContent("Confiance élevée");
    expect(card).toHaveTextContent("Voleur d'informations");
    expect(card).toHaveTextContent("contacte un serveur inconnu");
  });

  it("dit clairement quand un paquet est sans alerte", async () => {
    mockCheck.mockResolvedValue({
      data: [{ name: "lodash", ecosystem: "npm", status: "SCORED", tier: "LOW", suspicionProba: 0, reasons: [] }],
    });
    render(<SupplyChainPanel scanId={7} />);
    fireEvent.change(await screen.findByLabelText("Nom du paquet"), { target: { value: "lodash" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByText(/Aucun signal inquiétant/)).toBeInTheDocument();
  });

  it("explique quand le paquet n'existe pas et gère une erreur", async () => {
    mockCheck.mockResolvedValueOnce({ data: [{ name: "zzz", ecosystem: "npm", status: "NOT_FOUND", reasons: [] }] });
    render(<SupplyChainPanel scanId={7} />);
    fireEvent.change(await screen.findByLabelText("Nom du paquet"), { target: { value: "zzz" } });
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByText(/introuvable sur le registre public/)).toBeInTheDocument();

    mockCheck.mockRejectedValueOnce(new Error("boom"));
    fireEvent.click(screen.getByRole("button", { name: "Vérifier" }));
    expect(await screen.findByText(/Vérification impossible/)).toBeInTheDocument();
  });

  it("n'appelle pas l'API quand le nom est vide", async () => {
    render(<SupplyChainPanel scanId={7} />);
    const button = await screen.findByRole("button", { name: "Vérifier" });
    expect(button).toBeDisabled();
    expect(mockCheck).not.toHaveBeenCalled();
  });
});

describe("clés de correspondance SBOM / supply chain", () => {
  it("déduit l'écosystème depuis le PURL du SBOM", () => {
    expect(ecosystemOfPurl("pkg:npm/lodash@4.17.21")).toBe("npm");
    expect(ecosystemOfPurl("pkg:pypi/requests@2.31.0")).toBe("pypi");
    expect(ecosystemOfPurl("pkg:maven/com.google.guava/guava@32")).toBeNull();
    expect(ecosystemOfPurl("")).toBeNull();
    expect(ecosystemOfPurl(undefined)).toBeNull();
  });

  it("construit la même clé que le serveur (noms PyPI normalisés, noms npm inchangés)", () => {
    expect(supplyChainKey("npm", "@angular/core", "17.0.0")).toBe("npm:@angular/core@17.0.0");
    expect(supplyChainKey("pypi", "Django_REST.framework", "3.14.0")).toBe("pypi:django-rest-framework@3.14.0");
  });
});

describe("SupplyChainCell (colonne du tableau Dépendances)", () => {
  it("affiche un tiret pour un langage non couvert (Java, Go...)", () => {
    render(<SupplyChainCell brief={null} supported={false} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("indique « en attente » tant que l'analyse n'est pas finie", () => {
    render(<SupplyChainCell brief={null} supported pending />);
    expect(screen.getByText("en attente…")).toBeInTheDocument();
  });

  it("montre le niveau et le score d'un paquet analysé sans alerte", () => {
    render(<SupplyChainCell supported brief={{ name: "x", version: "1", tier: "LOW", status: "SCORED", suspicionProba: 0.078 }} />);
    expect(screen.getByText("Sans alerte")).toBeInTheDocument();
    expect(screen.getByText("8 %")).toBeInTheDocument();
  });

  it("montre « Connu malveillant » sans pourcentage", () => {
    render(<SupplyChainCell supported brief={{ name: "x", version: "1", tier: "KNOWN_MALICIOUS", status: "SCORED", suspicionProba: 1 }} />);
    expect(screen.getByText("Connu malveillant")).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("dit « non analysé » pour un paquet introuvable", () => {
    render(<SupplyChainCell supported brief={{ name: "x", version: "1", tier: null, status: "NOT_FOUND" }} />);
    expect(screen.getByText("non analysé")).toBeInTheDocument();
  });
});

describe("SupplyChainSummary (bandeau de l'onglet Dépendances)", () => {
  it("affiche les compteurs, les paquets signalés avec leurs raisons, et lance l'analyse au clic", () => {
    const onAnalyze = jest.fn();
    render(<SupplyChainSummary report={base} busy={false} onAnalyze={onAnalyze} compact />);
    expect(screen.getByText("Risque supply chain")).toBeInTheDocument();
    expect(screen.getByText("Connus malveillants")).toBeInTheDocument();
    expect(screen.getByText(/lit des secrets/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Réanalyser" }));
    expect(onAnalyze).toHaveBeenCalledTimes(1);
  });

  it("désactive le bouton pendant l'analyse", () => {
    render(<SupplyChainSummary report={base} busy onAnalyze={jest.fn()} />);
    expect(screen.getByRole("button", { name: "Analyse en cours…" })).toBeDisabled();
  });
});

describe("useSupplyChainReport", () => {
  const Probe: React.FC<{ scanId: number | null; enabled?: boolean }> = ({ scanId, enabled = true }) => {
    const { report, analyze } = useSupplyChainReport(scanId, enabled);
    return (
      <div>
        <span data-testid="total">{report ? report.totalComponents : "none"}</span>
        <button onClick={() => void analyze()}>go</button>
      </div>
    );
  };

  beforeEach(() => jest.clearAllMocks());

  it("charge le rapport du scan", async () => {
    mockGet.mockResolvedValue({ data: base });
    render(<Probe scanId={7} />);
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("5"));
    expect(mockGet).toHaveBeenCalledWith(7);
  });

  it("n'appelle pas l'API quand il est désactivé ou sans scan", async () => {
    render(<Probe scanId={7} enabled={false} />);
    render(<Probe scanId={null} />);
    await new Promise((r) => setTimeout(r, 30));
    expect(mockGet).not.toHaveBeenCalled();
  });

  it("met à jour le rapport après une analyse manuelle", async () => {
    mockGet.mockResolvedValue({ data: { ...base, totalComponents: 1 } });
    mockAnalyze.mockResolvedValue({ data: { ...base, totalComponents: 9 } });
    render(<Probe scanId={7} />);
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("1"));
    fireEvent.click(screen.getByRole("button", { name: "go" }));
    await waitFor(() => expect(screen.getByTestId("total")).toHaveTextContent("9"));
  });
});

describe("helpers", () => {
  it("formate les probabilités", () => {
    expect(formatProba(0.93)).toBe("93 %");
    expect(formatProba(0.0004)).toBe("0.0 %");
    expect(formatProba(null)).toBe("—");
  });
  it("donne une couleur par niveau", () => {
    expect(tierBadge("KNOWN_MALICIOUS")).toContain("bg-error");
    expect(tierBadge("REVIEW")).toContain("amber");
    expect(tierBadge(undefined)).toContain("outline");
  });
});
