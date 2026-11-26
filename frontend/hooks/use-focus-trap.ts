"use client";

import { useEffect, useRef } from "react";

const FOCUSABLE_SELECTOR = [
  'a[href]:not([tabindex="-1"])',
  'button:not([disabled]):not([tabindex="-1"])',
  'input:not([disabled]):not([type="hidden"]):not([tabindex="-1"])',
  'select:not([disabled]):not([tabindex="-1"])',
  'textarea:not([disabled]):not([tabindex="-1"])',
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/**
 * Keyboard focus trap + Escape handler + return-focus restoration for dialogs & drawers.
 */
export function useFocusTrap(
  active: boolean,
  onClose?: () => void,
  opts?: { initialFocusRef?: React.RefObject<HTMLElement | null>; trapFocus?: boolean }
) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const trapEnabled = opts?.trapFocus ?? true;

  useEffect(() => {
    if (!active) return;

    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const focusTimer = window.setTimeout(() => {
      if (opts?.initialFocusRef?.current) {
        opts.initialFocusRef.current.focus();
        return;
      }
      const root = containerRef.current;
      if (!root) return;
      const focusables = root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusables.length > 0) {
        focusables[0].focus();
      } else {
        root.focus();
      }
    }, 15);

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && onClose) {
        ev.preventDefault();
        onClose();
        return;
      }

      if (!trapEnabled || ev.key !== "Tab") return;
      const root = containerRef.current;
      if (!root) return;
      const focusables = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement
      );
      if (focusables.length === 0) return;

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const activeEl = document.activeElement;

      if (ev.shiftKey) {
        if (activeEl === first || !root.contains(activeEl)) {
          ev.preventDefault();
          last.focus();
        }
      } else if (activeEl === last || !root.contains(activeEl)) {
        ev.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener("keydown", onKeyDown);
      if (previousFocusRef.current && document.contains(previousFocusRef.current)) {
        previousFocusRef.current.focus();
      }
    };
  }, [active, onClose, opts?.initialFocusRef, trapEnabled]);

  return containerRef;
}
