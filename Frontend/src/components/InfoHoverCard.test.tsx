import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import InfoHoverCard from "./InfoHoverCard";

beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());

const Pair = () => (
  <div>
    <InfoHoverCard title="Carte A" body={<p>texte A</p>}>
      <span>A</span>
    </InfoHoverCard>
    <InfoHoverCard title="Carte B" body={<p>texte B</p>}>
      <span>B</span>
    </InfoHoverCard>
  </div>
);

const hover = (label: string) => fireEvent.mouseEnter(screen.getByText(label).parentElement as HTMLElement);
const leave = (label: string) => fireEvent.mouseLeave(screen.getByText(label).parentElement as HTMLElement);
const tick = (ms: number) => act(() => void jest.advanceTimersByTime(ms));

test("opens after a short hover, closes shortly after leaving", () => {
  render(<Pair />);
  hover("A");
  expect(screen.queryByRole("tooltip")).toBeNull(); // hover intent: not instant
  tick(200);
  expect(screen.getByRole("tooltip").textContent).toContain("texte A");
  leave("A");
  tick(200);
  expect(screen.queryByRole("tooltip")).toBeNull();
});

test("sweeping across triggers without stopping never opens a card", () => {
  render(<Pair />);
  hover("A");
  tick(50);
  leave("A");
  hover("B");
  tick(50);
  leave("B");
  tick(500);
  expect(screen.queryByRole("tooltip")).toBeNull();
});

test("only one card at a time: opening B closes A immediately, nothing is left behind", () => {
  render(<Pair />);
  hover("A");
  tick(200);
  hover("B"); // the pointer moved to B before A's close delay elapsed
  tick(200);
  const cards = screen.getAllByRole("tooltip");
  expect(cards).toHaveLength(1);
  expect(cards[0].textContent).toContain("texte B");
});

test("a card never captures the pointer (cannot get stuck under the cursor)", () => {
  render(<Pair />);
  hover("A");
  tick(200);
  expect(screen.getByRole("tooltip").className).toContain("pointer-events-none");
});

test("scrolling or Escape closes it (the trigger moved away from the cursor)", () => {
  render(<Pair />);
  hover("A");
  tick(200);
  fireEvent.scroll(window);
  expect(screen.queryByRole("tooltip")).toBeNull();
  hover("A");
  tick(200);
  fireEvent.keyDown(window, { key: "Escape" });
  expect(screen.queryByRole("tooltip")).toBeNull();
});

test("keyboard focus opens it at once and blur closes it", () => {
  render(<Pair />);
  fireEvent.focus(screen.getByText("A").parentElement as HTMLElement);
  expect(screen.getByRole("tooltip")).toBeTruthy();
  fireEvent.blur(screen.getByText("A").parentElement as HTMLElement);
  tick(200);
  expect(screen.queryByRole("tooltip")).toBeNull();
});

test("unmounting the trigger leaves no card behind", () => {
  const { unmount } = render(<Pair />);
  hover("A");
  tick(200);
  unmount();
  expect(screen.queryByRole("tooltip")).toBeNull();
});
