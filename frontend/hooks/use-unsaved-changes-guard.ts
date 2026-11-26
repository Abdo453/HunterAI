"use client";

import { useCallback, useEffect, useState } from "react";

export interface UnsavedChangesGuardOptions {
  isDirty: boolean;
  message?: string;
}

/**
 * Unsaved-changes guard protecting dirty Studio editor tabs and System Settings forms
 * against accidental browser reload/close or in-app discard.
 */
export function useUnsavedChangesGuard({ isDirty, message }: UnsavedChangesGuardOptions) {
  const [pendingAction, setPendingAction] = useState<(() => void) | null>(null);

  useEffect(() => {
    if (!isDirty) return;

    const onBeforeUnload = (ev: BeforeUnloadEvent) => {
      ev.preventDefault();
      ev.returnValue = message || "You have unsaved changes.";
      return ev.returnValue;
    };

    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [isDirty, message]);

  const requestAction = useCallback(
    (action: () => void) => {
      if (!isDirty) {
        action();
        return;
      }
      setPendingAction(() => action);
    },
    [isDirty]
  );

  const confirmDiscard = useCallback(() => {
    const fn = pendingAction;
    setPendingAction(null);
    if (fn) {
      fn();
    }
  }, [pendingAction]);

  const cancelDiscard = useCallback(() => {
    setPendingAction(null);
  }, []);

  return {
    hasPendingPrompt: pendingAction !== null,
    requestAction,
    confirmDiscard,
    cancelDiscard,
  } as const;
}
