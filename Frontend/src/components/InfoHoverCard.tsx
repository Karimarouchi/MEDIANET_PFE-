import React, { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

type Props = {
  title: string;
  children: React.ReactNode;
  body: React.ReactNode;
  align?: "center" | "left" | "right";
  className?: string;
};

/**
 * Hover card portaled to document.body so table overflow / badges do not clip it.
 * Stays open while the cursor is on the trigger or on the card itself.
 */
const InfoHoverCard: React.FC<Props> = ({ title, children, body, align = "center", className = "" }) => {
  const triggerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const hideTimer = useRef<number | null>(null);
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0 });

  const cancelHide = () => {
    if (hideTimer.current != null) {
      window.clearTimeout(hideTimer.current);
      hideTimer.current = null;
    }
  };

  const show = () => {
    cancelHide();
    setOpen(true);
  };

  const hideSoon = () => {
    cancelHide();
    hideTimer.current = window.setTimeout(() => setOpen(false), 160);
  };

  const place = () => {
    const el = triggerRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const width = 320;
    const gap = 10;
    let left =
      align === "left"
        ? r.left
        : align === "right"
          ? r.right - width
          : r.left + r.width / 2 - width / 2;
    left = Math.max(12, Math.min(left, window.innerWidth - width - 12));
    const h = cardRef.current?.offsetHeight || 240;
    const below = r.bottom + gap;
    const top = below + h > window.innerHeight - 12
      ? Math.max(12, r.top - h - gap)
      : below;
    setCoords({ top, left });
  };

  useEffect(() => {
    if (!open) return;
    const id = window.requestAnimationFrame(place);
    const onScroll = () => place();
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      window.cancelAnimationFrame(id);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open, align]);

  useEffect(() => () => cancelHide(), []);

  return (
    <>
      <div
        ref={triggerRef}
        className={`inline-flex max-w-full cursor-help align-middle ${className}`}
        onMouseEnter={show}
        onMouseLeave={hideSoon}
        onFocus={show}
        onBlur={hideSoon}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
      {open &&
        createPortal(
          <div
            ref={cardRef}
            role="tooltip"
            className="fixed z-[200] w-80 rounded-2xl border border-outline-variant/40 bg-surface-container-highest p-4 shadow-2xl shadow-black/50"
            style={{ top: coords.top, left: coords.left }}
            onMouseEnter={show}
            onMouseLeave={hideSoon}
          >
            <p className="font-headline text-sm font-bold text-on-surface mb-2">{title}</p>
            <div className="text-[11px] leading-relaxed text-on-surface-variant space-y-1.5">
              {body}
            </div>
          </div>,
          document.body,
        )}
    </>
  );
};

export default InfoHoverCard;
