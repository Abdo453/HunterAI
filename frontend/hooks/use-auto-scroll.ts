"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Sticky auto-scroll hook adapted from PentAGI's useAutoScroll pattern (MIT License,
 * retained in THIRD_PARTY_LICENSES/PENTAGI_MIT.txt) for React 19 + Obsidian Sentinel.
 *
 * Keeps scroll pinned to the bottom while the operator is near the bottom,
 * pauses auto-scroll when the operator scrolls upward to inspect history,
 * and tracks unread count for the sticky `end-4 bottom-4` badge.
 */
export interface IdentifiableItem {
  id: string;
}

export function useAutoScroll<T extends IdentifiableItem>(
  items: readonly T[] | undefined,
  resetKey: string | null | undefined
) {
  const containerElementRef = useRef<HTMLDivElement | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  const [isScrolledToBottom, setIsScrolledToBottom] = useState<boolean>(true);
  const [unreadCount, setUnreadCount] = useState<number>(0);

  const isScrolledToBottomRef = useRef<boolean>(true);
  const isScrollAnimatingRef = useRef<boolean>(false);
  const prevResetKeyRef = useRef<string | null | undefined>(resetKey);
  const prevLengthRef = useRef<number>(items?.length ?? 0);
  const prevLastIdRef = useRef<string | null>(items && items.length > 0 ? items[items.length - 1].id : null);

  const scrollToEnd = useCallback((behavior: ScrollBehavior = "smooth") => {
    const endEl = endRef.current;
    const container = containerElementRef.current;
    isScrollAnimatingRef.current = behavior === "smooth";
    isScrolledToBottomRef.current = true;
    setIsScrolledToBottom(true);
    setUnreadCount(0);
    if (endEl) {
      endEl.scrollIntoView({ behavior, block: "end" });
    } else if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }, []);

  const handleScroll = useCallback(() => {
    const container = containerElementRef.current;
    if (!container) return;

    const { clientHeight, scrollHeight, scrollTop } = container;
    const distanceFromBottom = scrollHeight - scrollTop - clientHeight;

    if (distanceFromBottom <= 16) {
      isScrollAnimatingRef.current = false;
      if (!isScrolledToBottomRef.current) {
        isScrolledToBottomRef.current = true;
        setIsScrolledToBottom(true);
        setUnreadCount(0);
      }
    } else if (isScrolledToBottomRef.current && !isScrollAnimatingRef.current) {
      isScrolledToBottomRef.current = false;
      setIsScrolledToBottom(false);
    }
  }, []);

  const containerRef = useCallback(
    (node: HTMLDivElement | null) => {
      if (containerElementRef.current) {
        containerElementRef.current.removeEventListener("scroll", handleScroll);
      }
      containerElementRef.current = node;
      if (node) {
        node.addEventListener("scroll", handleScroll, { passive: true });
      }
    },
    [handleScroll]
  );

  useEffect(() => {
    const currentLength = items?.length ?? 0;
    const currentLastId = items && items.length > 0 ? items[items.length - 1].id : null;
    const isReset = prevResetKeyRef.current !== resetKey;

    if (isReset) {
      prevResetKeyRef.current = resetKey;
      prevLengthRef.current = currentLength;
      prevLastIdRef.current = currentLastId;
      isScrolledToBottomRef.current = true;
      isScrollAnimatingRef.current = false;
      setIsScrolledToBottom(true);
      setUnreadCount(0);
      if (endRef.current) {
        endRef.current.scrollIntoView({ behavior: "auto", block: "end" });
      }
      return;
    }

    const addedDelta = Math.max(0, currentLength - prevLengthRef.current);
    const tailChanged = currentLastId !== prevLastIdRef.current;

    prevLengthRef.current = currentLength;
    prevLastIdRef.current = currentLastId;

    const container = containerElementRef.current;
    if (!container) return;

    const hasVerticalScroll = container.scrollHeight - container.clientHeight > 8;
    if (!hasVerticalScroll) {
      if (!isScrolledToBottomRef.current) {
        isScrolledToBottomRef.current = true;
        setIsScrolledToBottom(true);
        setUnreadCount(0);
      }
      return;
    }

    if (isScrolledToBottomRef.current) {
      if (endRef.current) {
        endRef.current.scrollIntoView({ behavior: "auto", block: "end" });
      } else {
        container.scrollTop = container.scrollHeight;
      }
    } else if (addedDelta > 0 || tailChanged) {
      setUnreadCount((prev) => prev + Math.max(1, addedDelta));
    }
  }, [items, resetKey]);

  return {
    containerRef,
    endRef,
    hasNewMessages: unreadCount > 0,
    unreadCount,
    isScrolledToBottom,
    scrollToEnd,
  } as const;
}
