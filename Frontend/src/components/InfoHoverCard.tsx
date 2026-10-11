import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

type Props = {
  title: string;
  children: React.ReactNode;
  body: React.ReactNode;
  align?: "center" | "left" | "right";
  className?: string;
};

/** Only one card is ever open: opening a card closes the previous one (no stacked or stuck cards). */
let closeActive: (() => void) | null = null;

const OPEN_DELAY = 140; // hover intent: sweeping the pointer across a table does not flash cards
const CLOSE_DELAY = 90;
const WIDTH = 320;
const GAP = 10;

/**
 * Information card shown on hover or keyboard focus, portaled to document.body so table overflow does not clip it.
 *
 * It is purely informative and does not capture the pointer: the cursor can never get "stuck" on it, and moving along
 * a table never leaves a card behind. It closes on leave, on scroll, on Escape and when another card opens, and it is
 * placed after being measured, so it does not jump.
 */
const InfoHoverCard: React.FC<Props> = ({ title, children, body, align = "center", className = "" }) => {
  const triggerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const timer = useRef<number | null>(null);
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<{ top: number; left: number } | null>(null);

  const clearTimer = () => {
    if (timer.current != null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  };

  const close = useCallback(() => {
    clearTimer();
    setOpen(false);
    setCoords(null);
    if (closeActive === close) closeActive = null;
  }, []);

  const openNow = useCallback(() => {
    clearTimer();
    if (closeActive && closeActive !== close) closeActive();
    closeActive = close;
    setOpen(true);
  }, [close]);

  const scheduleOpen = () => {
    clearTimer();
    timer.current = window.setTimeout(openNow, OPEN_DELAY);
  };

  const scheduleClose = () => {
    clearTimer();
    timer.current = window.setTimeout(close, CLOSE_DELAY);
  };

  // measure then place: below the trigger, above it when there is no room, always inside the window
  useLayoutEffect(() => {
    if (!open) return;
    const trigger = triggerRef.current;
    const card = cardRef.current;
    if (!trigger || !card) return;
    const r = trigger.getBoundingClientRect();
    const h = card.offsetHeight;
    let left = align === "left" ? r.left : align === "right" ? r.right - WIDTH : r.left + r.width / 2 - WIDTH / 2;
    left = Math.max(12, Math.min(left, window.innerWidth - WIDTH - 12));
    const below = r.bottom + GAP;
    const top = below + h > window.innerHeight - 12 ? Math.max(12, r.top - h - GAP) : below;
    setCoords({ top, left });
  }, [open, align]);

  useEffect(() => {
    if (!open) return;
    const onScroll = () => close();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
      window.removeEventListener("keydown", onKey);
    };
  }, [open, close]);

  useEffect(
    () => () => {
      clearTimer();
      if (closeActive === close) closeActive = null;
    },
    [close],
  );

  return (
    <>
      <div
        ref={triggerRef}
        className={`inline-flex max-w-full cursor-help align-middle ${className}`}
        onMouseEnter={scheduleOpen}
        onMouseLeave={scheduleClose}
        onFocus={openNow}
        onBlur={scheduleClose}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
      {open &&
        createPortal(
          <div
            ref={cardRef}
            role="tooltip"
            className="fixed z-[200] w-80 rounded-2xl border border-outline-variant/40 bg-surface-container-highest p-4 shadow-2xl shadow-black/50 pointer-events-none"
            // hidden until measured, so it never appears at the wrong place for one frame
            style={{ top: coords?.top ?? 0, left: coords?.left ?? 0, visibility: coords ? "visible" : "hidden" }}
          >
            <p className="font-headline text-sm font-bold text-on-surface mb-2">{title}</p>
            <div className="text-[11px] leading-relaxed text-on-surface-variant space-y-1.5">{body}</div>
          </div>,
          document.body,
        )}
    </>
  );
};

export default InfoHoverCard;
