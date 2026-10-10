import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import DeadlineBadge, { countdownLabel, daysLeft } from "./DeadlineBadge";

const NOW = new Date(2026, 9, 4, 21, 0, 0); // 4 Oct 2026, evening

describe("daysLeft", () => {
  test("counts calendar days, whatever the hour", () => {
    expect(daysLeft("2026-11-04", NOW)).toBe(31);
    expect(daysLeft("2026-10-05", NOW)).toBe(1);
    expect(daysLeft("2026-10-04", NOW)).toBe(0);
    expect(daysLeft("2026-10-01", NOW)).toBe(-3);
  });

  test("returns null without a usable date", () => {
    expect(daysLeft(null, NOW)).toBeNull();
    expect(daysLeft("", NOW)).toBeNull();
    expect(daysLeft("n'importe quoi", NOW)).toBeNull();
  });
});

test("countdown labels", () => {
  expect(countdownLabel(31)).toBe("31 j restants");
  expect(countdownLabel(0)).toBe("Aujourd'hui");
  expect(countdownLabel(-3)).toBe("3 j de retard");
  expect(countdownLabel(null)).toBe("");
});

describe("DeadlineBadge", () => {
  test("shows the countdown for a future date", () => {
    const future = new Date();
    future.setDate(future.getDate() + 20);
    const iso = `${future.getFullYear()}-${String(future.getMonth() + 1).padStart(2, "0")}-${String(future.getDate()).padStart(2, "0")}`;
    render(<DeadlineBadge deadline={iso} label="MEP" />);
    expect(screen.getByTestId("deadline-countdown").textContent).toBe("20 j restants");
    expect(screen.getByText(/MEP/)).toBeTruthy();
  });

  test("warns when there is no deadline and lets the date be set", () => {
    const onChange = jest.fn();
    render(<DeadlineBadge deadline={null} onChange={onChange} />);
    expect(screen.getByText(/Aucune deadline/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Nouvelle deadline"), { target: { value: "2027-01-10" } });
    expect(onChange).toHaveBeenCalledWith("2027-01-10");
  });

  test("an existing deadline can be modified through the pencil", () => {
    const onChange = jest.fn();
    render(<DeadlineBadge deadline="2099-01-01" onChange={onChange} />);
    fireEvent.click(screen.getByTitle("Modifier la deadline"));
    fireEvent.change(screen.getByLabelText("Nouvelle deadline"), { target: { value: "2099-02-02" } });
    expect(onChange).toHaveBeenCalledWith("2099-02-02");
  });

  test("compact mode has no edit control and no empty-state hint", () => {
    const { container, rerender } = render(<DeadlineBadge deadline="2099-01-01" onChange={() => {}} compact />);
    expect(screen.queryByTitle("Modifier la deadline")).toBeNull();
    rerender(<DeadlineBadge deadline={null} compact />);
    expect(container.textContent).toBe("");
  });
});
