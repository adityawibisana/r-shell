// App-wide clipboard for the remote file browser. Entries remember the
// connection they were copied from, so a paste in another session's tab
// copies across connections instead of running `cp` on the wrong server.
//
// Copy/cut also stages the selection locally (one fixed folder, replaced by
// every new copy) so a paste into another connection only uploads. Above the
// backend's 500 MB limit the clipboard stays a plain reference and the paste
// copies live between the two sessions.

import { useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface FileClipboardEntry {
  name: string;
  path: string;
  type: "file" | "directory";
}

/**
 * `staging`: the local copy is still downloading. `ready`: paste uploads from
 * the local copy. `reference`: nothing staged (too large or staging failed);
 * paste copies live from the source session.
 */
export type FileClipboardStatus = "staging" | "ready" | "reference";

export interface FileClipboard {
  connectionId: string;
  operation: "copy" | "cut";
  files: FileClipboardEntry[];
  status: FileClipboardStatus;
  /** Identifies this copy's contents in the single local stage folder. */
  stageToken: string;
}

type StageOutcome =
  | { status: "ready"; bytes: number }
  | { status: "tooLarge"; bytes: number };

let current: FileClipboard | null = null;
let nextToken = 0;
const listeners = new Set<() => void>();

export function getFileClipboard(): FileClipboard | null {
  return current;
}

function publish(next: FileClipboard | null): void {
  current = next;
  for (const listener of listeners) listener();
}

/** Replace the clipboard without touching the local stage (tests, internal). */
export function setFileClipboard(next: FileClipboard | null): void {
  publish(next);
}

/**
 * Put `files` on the clipboard and stage them locally, replacing any earlier
 * staged copy. Resolves with the final status of THIS copy, or `null` when a
 * newer copy or a clear replaced it first.
 */
export async function copyToFileClipboard(
  connectionId: string,
  operation: "copy" | "cut",
  files: FileClipboardEntry[],
): Promise<FileClipboardStatus | null> {
  const stageToken = `${Date.now()}-${++nextToken}`;
  const entry: FileClipboard = { connectionId, operation, files, status: "staging", stageToken };
  publish(entry);
  let status: FileClipboardStatus;
  try {
    const outcome = await invoke<StageOutcome>("stage_clipboard", {
      connectionId,
      stageToken,
      entries: files.map((f) => ({ path: f.path, isDirectory: f.type === "directory" })),
    });
    status = outcome.status === "ready" ? "ready" : "reference";
  } catch (error) {
    if (current !== entry) return null;
    console.warn("[FileClipboard] Staging failed, pasting live instead:", error);
    status = "reference";
  }
  if (current !== entry) return null;
  publish({ ...entry, status });
  return status;
}

/** Empty the clipboard and the local stage. */
export function clearFileClipboard(): void {
  publish(null);
  invoke("clear_clipboard_stage").catch((error: unknown) => {
    console.warn("[FileClipboard] Failed to clear the local stage:", error);
  });
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useFileClipboard(): FileClipboard | null {
  return useSyncExternalStore(subscribe, getFileClipboard, getFileClipboard);
}
