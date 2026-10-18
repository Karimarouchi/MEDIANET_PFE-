import { plannedGraph } from "./CiRepoAnalysisPanel";

describe("plannedGraph", () => {
  it("turns the analysis into planned graph nodes with a test verdict per part", () => {
    const g = plannedGraph({
      plannedSteps: ["clone", "maven-backend", "npm-frontend", "vulnix-scan"],
      prompt: "",
      parts: [
        { kind: "maven", dir: "Backend", step: "maven-backend", stack: "Spring Boot 3.2.3 · Java 17", hasTests: false, testFiles: 0, missing: "aucun test", commands: [], targets: [], rules: [], warnings: [] },
        { kind: "npm", dir: "Frontend", step: "npm-frontend", stack: "React 18, Vite 5", hasTests: true, testFiles: 4, missing: null, commands: [], targets: [], rules: [], warnings: [] },
      ],
    });
    expect(g.steps.map((s) => [s.name, s.state])).toEqual([
      ["clone", "planned"], ["maven-backend", "planned"], ["npm-frontend", "planned"], ["vulnix-scan", "planned"],
    ]);
    expect(g.outcomes[-2]).toEqual({ tone: "warn", text: "Aucun test · Spring Boot 3.2.3 · Java 17" });
    expect(g.outcomes[-3]).toEqual({ tone: "ok", text: "4 fichier(s) de test · React 18, Vite 5" });
  });
});
