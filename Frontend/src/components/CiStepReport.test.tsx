import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import { CiLog, CiStepReport } from "./CiStepReport";

const E = "\x1b";

describe("CiStepReport", () => {
  it("lists failed tests and why they failed", () => {
    render(<CiStepReport stepName="npm-frontend" state="failure" lines={[
      `${E}[41m${E}[1m FAIL ${E}[22m${E}[49m src/Menu.test.jsx${E}[2m > ${E}[22mMenu${E}[2m > ${E}[22mshows Huiles`,
      "TestingLibraryElementError: Found multiple elements with the text: Huiles",
    ]} />);
    expect(screen.getByText("1 test en échec")).toBeInTheDocument();
    expect(screen.getByText(/Menu › shows Huiles/)).toBeInTheDocument();
    expect(screen.getByText(/« Huiles » apparaît plusieurs fois/)).toBeInTheDocument();
  });

  it("summarises the blocking vulnerabilities", () => {
    render(<CiStepReport stepName="vulnix-scan" state="failure" lines={[
      "  BLOQUANT CRITICAL  CVE-2024-1      lodash (KEV)",
      "Barriere Vulnix : ECHEC, 1 vulnerabilite(s) bloquante(s) (critique, elevee ou KEV).",
    ]} />);
    expect(screen.getByText("1 vulnérabilité bloquante : 1 critique, dont 1 activement exploitée (KEV).")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-1")).toBeInTheDocument();
    expect(screen.getByText("KEV")).toBeInTheDocument();
  });

  it("shows nothing for a step without failure details", () => {
    const { container } = render(<CiStepReport stepName="clone" state="success" lines={["ok"]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("CiLog", () => {
  it("shows colours instead of escape codes and can keep only error lines", () => {
    render(<CiLog lines={[`${E}[32m✓${E}[39m test ok`, `${E}[41m FAIL ${E}[49m src/a.test.js > a`]} empty="—" />);
    expect(screen.queryByText(/\[32m/)).toBeNull();
    expect(screen.getByText("test ok", { exact: false })).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/Seulement les lignes d'erreur \(1\)/));
    expect(screen.queryByText("test ok", { exact: false })).toBeNull();
    expect(screen.getByText(/src\/a\.test\.js > a/)).toBeInTheDocument();
  });
});
