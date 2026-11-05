import "@fontsource/cascadia-mono/400.css";
import "@fontsource/cascadia-mono/700.css";

const FONT_LOAD_TIMEOUT_MS = 1000;

/**
 * Fetches the embedded fonts' Latin files. xterm measures its cell size when a
 * terminal opens and does not re-measure when a webfont arrives later, so this
 * must settle before the first terminal mounts. Never rejects: a font that
 * fails to load falls back to the next family in the stack.
 */
export function loadEmbeddedFonts(): Promise<unknown> {
  return Promise.race([
    Promise.allSettled([
      document.fonts.load('400 14px "Cascadia Mono"'),
      document.fonts.load('700 14px "Cascadia Mono"'),
    ]),
    new Promise((resolve) => setTimeout(resolve, FONT_LOAD_TIMEOUT_MS)),
  ]);
}
