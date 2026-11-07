import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import ConfigurationPanel from "./ConfigurationPanel";
import DastPanel from "./DastPanel";
import { findingFamily } from "../utils/findingFamily";
import {
  configSeverityLabel,
  countConfigBySeverity,
  groupConfigByCategory,
  splitConfigFindings,
} from "../utils/configView";
import type { ConfigFindingDto, CveDto } from "../services/api";

const cfg = (id: number, over: Partial<ConfigFindingDto> = {}): ConfigFindingDto => ({
  id,
  ruleId: `R-${id}`,
  ruleIds: [`R-${id}`],
  title: `Défaut ${id}`,
  description: null,
  resolution: null,
  severity: "HIGH",
  category: "DOCKERFILE",
  file: "Dockerfile",
  startLine: id,
  endLine: id,
  resource: null,
  sources: ["trivy"],
  referenceUrl: null,
  ...over,
});

describe("findingFamily", () => {
  test("the kind decides first", () => {
    expect(findingFamily({ findingKind: "DAST", cveId: "CVE-2020-1" })).toBe("dast");
    expect(findingFamily({ findingKind: "CODE_WEAKNESS" })).toBe("code");
    expect(findingFamily({ findingKind: "DEPENDENCY", cveId: "ZAP-10" })).toBe("dependency");
  });

  test("without a kind, ZAP and Nuclei are DAST and Semgrep is code", () => {
    expect(findingFamily({ cveId: "ZAP-10038", source: "zaproxy" })).toBe("dast");
    expect(findingFamily({ cveId: "NUCLEI-x", source: "nuclei" })).toBe("dast");
    expect(findingFamily({ cveId: "CWE-79", source: "semgrep" })).toBe("code");
    expect(findingFamily({ cveId: "CVE-2020-1", source: "grype" })).toBe("dependency");
  });
});

describe("configView", () => {
  test("a severity-less Checkov finding is labelled Non évaluée, not Moyenne", () => {
    expect(configSeverityLabel("UNKNOWN")).toBe("Non évaluée");
    expect(configSeverityLabel(null)).toBe("Non évaluée");
    expect(configSeverityLabel("MEDIUM")).toBe("Moyenne");
  });

  test("info-level findings are split from the main list, not dropped", () => {
    const { main, low } = splitConfigFindings([cfg(1, { severity: "INFO" }), cfg(2, { severity: "LOW" }), cfg(3, { severity: "UNKNOWN" })]);
    expect(main.map(f => f.id)).toEqual([2, 3]);
    expect(low.map(f => f.id)).toEqual([1]);
  });

  test("sorted by severity then place; grouped by category in a fixed order", () => {
    const list = [
      cfg(1, { severity: "LOW", category: "TERRAFORM" }),
      cfg(2, { severity: "HIGH", category: "KUBERNETES" }),
      cfg(3, { severity: "CRITICAL", category: "DOCKERFILE" }),
    ];
    expect(splitConfigFindings(list).main.map(f => f.id)).toEqual([3, 2, 1]);
    expect(groupConfigByCategory(list).map(g => g.category)).toEqual(["DOCKERFILE", "KUBERNETES", "TERRAFORM"]);
    expect(countConfigBySeverity(list)).toEqual({ LOW: 1, HIGH: 1, CRITICAL: 1 });
  });
});

describe("ConfigurationPanel", () => {
  test("shows the findings by category and says they are not CVEs", () => {
    render(
      <ConfigurationPanel
        loading={false}
        findings={[cfg(1), cfg(2, { category: "KUBERNETES", file: "k8s/deployment.yaml", sources: ["trivy", "checkov"] })]}
      />,
    );
    expect(screen.getAllByTestId("config-row")).toHaveLength(2);
    expect(screen.getByText("Kubernetes")).toBeTruthy();
    expect(screen.getByText(/ne bloquent pas le pipeline/)).toBeTruthy();
    expect(screen.getByText(/Ce ne sont pas des CVE/)).toBeTruthy();
  });

  test("info-level suggestions stay hidden until asked", () => {
    render(<ConfigurationPanel loading={false} findings={[cfg(1), cfg(2, { severity: "INFO", title: "Style hint" })]} />);
    expect(screen.queryByText("Style hint")).toBeNull();
    fireEvent.click(screen.getByTestId("config-low-toggle"));
    expect(screen.getByText("Style hint")).toBeTruthy();
  });

  test("empty and loading states", () => {
    const { rerender } = render(<ConfigurationPanel loading={false} findings={[]} />);
    expect(screen.getByText("Aucun défaut de configuration")).toBeTruthy();
    rerender(<ConfigurationPanel loading findings={[]} />);
    expect(screen.getByText(/Chargement/)).toBeTruthy();
  });

  test("a row opens to show the fix", () => {
    render(<ConfigurationPanel loading={false} findings={[cfg(1, { resolution: "Ajoutez USER app" })]} />);
    expect(screen.queryByText(/Ajoutez USER app/)).toBeNull();
    fireEvent.click(screen.getByTestId("config-row"));
    expect(screen.getByText(/Ajoutez USER app/)).toBeTruthy();
  });
});

describe("DastPanel", () => {
  const alert = { id: 1, cveId: "NUCLEI-codeigniter-env", packageName: "Codeigniter - .env File Discovery", severity: "HIGH", cweId: "CWE-552", filePath: "http://t/.env", source: "nuclei", sources: "NUCLEI" } as unknown as CveDto;

  test("lists the alert with its URL and CWE, with no package column", () => {
    render(<DastPanel alerts={[alert]} />);
    expect(screen.getAllByTestId("dast-row")).toHaveLength(1);
    expect(screen.getByText("http://t/.env")).toBeTruthy();
    expect(screen.getByText("CWE-552")).toBeTruthy();
    expect(screen.getByText("Nuclei")).toBeTruthy();
    expect(screen.queryByText("Package")).toBeNull();
  });

  test("empty state", () => {
    render(<DastPanel alerts={[]} />);
    expect(screen.getByText("Aucune alerte applicative")).toBeTruthy();
  });
});
