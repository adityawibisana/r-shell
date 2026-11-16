// App-wide clipboard for the remote file browser. Entries remember the
// connection they were copied from, so a paste in another session's tab
// copies across connections instead of running `cp` on the wrong server.

import { useSyncExternalStore } from "react";

export interface FileClipboardEntry {
  name: string;
  path: string;
  type: "file" | "directory";
}

export interface FileClipboard {
  connectionId: string;
  operation: "copy" | "cut";
  files: FileClipboardEntry[];
}

let current: FileClipboard | null = null;
const listeners = new Set<() => void>();

export function getFileClipboard(): FileClipboard | null {
  return current;
}

export function setFileClipboard(next: FileClipboard | null): void {
  current = next;
  for (const listener of listeners) listener();
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
