/**
 * Tests unitaires pour le composant ConfirmModal.
 * Vérifie le rendu conditionnel et les callbacks onConfirm/onCancel.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import ConfirmModal from "./ConfirmModal";

// ──────────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────────
const defaultProps = {
  open: true,
  message: "Voulez-vous vraiment effectuer cette action ?",
  onConfirm: jest.fn(),
  onCancel: jest.fn(),
};

beforeEach(() => {
  jest.clearAllMocks();
});

// ──────────────────────────────────────────────────────────────────────────────
// Rendu conditionnel
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — rendu conditionnel", () => {
  test("affiche la modal quand open=true", () => {
    render(<ConfirmModal {...defaultProps} open={true} />);
    expect(screen.getByText(defaultProps.message)).toBeInTheDocument();
  });

  test("n'affiche pas la modal quand open=false", () => {
    render(<ConfirmModal {...defaultProps} open={false} />);
    expect(screen.queryByText(defaultProps.message)).not.toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Titre et message
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — titre et message", () => {
  test("affiche le titre par défaut 'Confirmation'", () => {
    render(<ConfirmModal {...defaultProps} />);
    expect(screen.getByText("Confirmation")).toBeInTheDocument();
  });

  test("affiche un titre personnalisé si fourni", () => {
    render(<ConfirmModal {...defaultProps} title="Supprimer ce client ?" />);
    expect(screen.getByText("Supprimer ce client ?")).toBeInTheDocument();
  });

  test("affiche le message passé en props", () => {
    render(<ConfirmModal {...defaultProps} message="Ceci est irréversible." />);
    expect(screen.getByText("Ceci est irréversible.")).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Boutons — labels
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — labels des boutons", () => {
  test("affiche 'Confirmer' et 'Annuler' par défaut", () => {
    render(<ConfirmModal {...defaultProps} />);
    expect(screen.getByText("Confirmer")).toBeInTheDocument();
    expect(screen.getByText("Annuler")).toBeInTheDocument();
  });

  test("affiche des labels personnalisés si fournis", () => {
    render(
      <ConfirmModal
        {...defaultProps}
        confirmLabel="Oui, supprimer"
        cancelLabel="Non, garder"
      />
    );
    expect(screen.getByText("Oui, supprimer")).toBeInTheDocument();
    expect(screen.getByText("Non, garder")).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Callbacks
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — callbacks onConfirm / onCancel", () => {
  test("appelle onConfirm quand le bouton de confirmation est cliqué", () => {
    const onConfirm = jest.fn();
    render(<ConfirmModal {...defaultProps} onConfirm={onConfirm} />);
    fireEvent.click(screen.getByText("Confirmer"));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  test("appelle onCancel quand le bouton d'annulation est cliqué", () => {
    const onCancel = jest.fn();
    render(<ConfirmModal {...defaultProps} onCancel={onCancel} />);
    fireEvent.click(screen.getByText("Annuler"));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  test("n'appelle pas onConfirm si le bouton Annuler est cliqué", () => {
    const onConfirm = jest.fn();
    render(<ConfirmModal {...defaultProps} onConfirm={onConfirm} />);
    fireEvent.click(screen.getByText("Annuler"));
    expect(onConfirm).not.toHaveBeenCalled();
  });

  test("n'appelle pas onCancel si le bouton Confirmer est cliqué", () => {
    const onCancel = jest.fn();
    render(<ConfirmModal {...defaultProps} onCancel={onCancel} />);
    fireEvent.click(screen.getByText("Confirmer"));
    expect(onCancel).not.toHaveBeenCalled();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Mode danger
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — mode danger", () => {
  test("affiche l'icône 'warning' quand danger=true", () => {
    render(<ConfirmModal {...defaultProps} danger={true} />);
    expect(screen.getByText("warning")).toBeInTheDocument();
  });

  test("affiche l'icône 'help' quand danger=false", () => {
    render(<ConfirmModal {...defaultProps} danger={false} />);
    expect(screen.getByText("help")).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Clavier — Escape / Enter
// ──────────────────────────────────────────────────────────────────────────────

describe("ConfirmModal — raccourcis clavier", () => {
  test("appelle onCancel quand la touche Escape est pressée", () => {
    const onCancel = jest.fn();
    render(<ConfirmModal {...defaultProps} onCancel={onCancel} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  test("appelle onConfirm quand la touche Enter est pressée", () => {
    const onConfirm = jest.fn();
    render(<ConfirmModal {...defaultProps} onConfirm={onConfirm} />);
    fireEvent.keyDown(window, { key: "Enter" });
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
