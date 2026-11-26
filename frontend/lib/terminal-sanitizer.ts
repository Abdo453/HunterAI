/**
 * Slice-based ANSI / OSC / C0-C1 / Bidi terminal output sanitizer.
 *
 * Adapted cleanly from PentAGI's slice-based terminal-sanitizer pattern (MIT License,
 * retained in THIRD_PARTY_LICENSES/PENTAGI_MIT.txt) with HunterAI modifications:
 * - Zero regex backtracking (linear O(n) char-code scan + slice extraction).
 * - Safe 64KB chunk processing (`sanitizeTerminalChunks`) for large live streams.
 * - Preserves full Arabic & multilingual Unicode blocks while stripping Bidi spoofing
 *   controls (U+061C, U+200E..U+200F, U+202A..U+202E, U+2066..U+2069).
 * - Strips C0/C1 controls (except TAB, LF, CR), non-SGR CSI sequences, unsafe OSC
 *   sequences (OSC 0/4/10/11/12, javascript:/data: hyperlinks), and DCS/APC/PM/SOS bodies.
 * - Provides `stripSgrSequences` and `parseSgrSegments` for React-native read-only rendering
 *   with zero `dangerouslySetInnerHTML`.
 */

const BINARY_SAMPLE_SIZE = 512;
const BINARY_CONTROL_RATIO = 0.1;
const MAX_CSI_LENGTH = 256;
const MAX_OSC_LENGTH = 2048;
const MAX_STRING_SEQUENCE_LENGTH = 100_000;
export const TERMINAL_CHUNK_BYTES = 65_536;

export const SAFE_PROTOCOLS = ["http://", "https://", "mailto:", "ssh://", "telnet://"] as const;

export function isBidiControl(code: number): boolean {
  return (
    code === 0x061c ||
    (code >= 0x200e && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

export function needsSanitization(input: string): boolean {
  if (!input) {
    return false;
  }

  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);

    if (code === 0x09 || code === 0x0a || code === 0x0d) {
      continue;
    }

    if (code >= 0x20 && code <= 0x7e) {
      continue;
    }

    if (code >= 0xa0) {
      if (code >= 0xd800 && code <= 0xdbff) {
        if (i + 1 < input.length) {
          const next = input.charCodeAt(i + 1);
          if (next >= 0xdc00 && next <= 0xdfff) {
            i++;
            continue;
          }
        }
        return true;
      }

      if ((code >= 0xdc00 && code <= 0xdfff) || code === 0xfffd) {
        return true;
      }

      if (isBidiControl(code)) {
        return true;
      }

      continue;
    }

    return true;
  }

  return false;
}

export function isBinaryContent(input: string): boolean {
  if (input.length < 32) {
    return input.includes("\x00");
  }

  let controlCount = 0;
  const sampleSize = Math.min(input.length, BINARY_SAMPLE_SIZE);

  for (let i = 0; i < sampleSize; i++) {
    const code = input.charCodeAt(i);
    if (code === 0x00) {
      return true;
    }

    if (code >= 0xd800 && code <= 0xdfff) {
      if (code <= 0xdbff && i + 1 < input.length) {
        const next = input.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          i++;
          continue;
        }
      }
      return true;
    }

    if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d && code !== 0x1b) {
      controlCount++;
    }
    if (code >= 0x80 && code <= 0x9f) {
      controlCount++;
    }
  }

  return controlCount / sampleSize > BINARY_CONTROL_RATIO;
}

function isOscSafe(content: string): boolean {
  if (!content.startsWith("8;")) {
    return false;
  }
  const secondSemicolon = content.indexOf(";", 2);
  if (secondSemicolon === -1) {
    return false;
  }
  const uri = content.slice(secondSemicolon + 1);
  if (!uri) {
    return true;
  }
  const uriLower = uri.toLowerCase();
  return SAFE_PROTOCOLS.some((protocol) => uriLower.startsWith(protocol));
}

function parseCsiSequence(input: string, start: number): { end: number; final: string } {
  let i = start;
  while (i < input.length && i - start < MAX_CSI_LENGTH) {
    const code = input.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return { end: -1, final: "" };
    }
    i++;
    if (code >= 0x40 && code <= 0x7e) {
      return { end: i, final: String.fromCharCode(code) };
    }
  }
  return { end: -1, final: "" };
}

function parseOscSequence(input: string, start: number): number {
  let i = start;
  while (i < input.length && i - start < MAX_OSC_LENGTH) {
    const code = input.charCodeAt(i);
    if (code === 0x07) {
      return i + 1;
    }
    if (code === 0x1b && i + 1 < input.length && input.charCodeAt(i + 1) === 0x5c) {
      return i + 2;
    }
    if (code < 0x20 && code !== 0x07) {
      return -1;
    }
    if (code === 0x7f || (code >= 0x80 && code <= 0x9f)) {
      return -1;
    }
    i++;
  }
  return -1;
}

function skipToST(input: string, start: number): number {
  let i = start;
  const limit = Math.min(input.length, start + MAX_STRING_SEQUENCE_LENGTH);
  while (i < limit) {
    const code = input.charCodeAt(i);
    if (code === 0x9c) {
      return i + 1;
    }
    if (code === 0x1b && i + 1 < input.length && input.charCodeAt(i + 1) === 0x5c) {
      return i + 2;
    }
    i++;
  }
  return i;
}

export function sanitizeTerminalOutput(input: string, opts?: { preserveSgr?: boolean }): string {
  if (!input) {
    return input;
  }
  if (isBinaryContent(input)) {
    return "[binary data]";
  }

  const preserveSgr = opts?.preserveSgr ?? true;
  const result: string[] = [];
  let i = 0;
  let safeStart = 0;

  while (i < input.length) {
    const code = input.charCodeAt(i);

    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d) {
      i++;
      continue;
    }

    if (code >= 0xa0) {
      if (code >= 0xd800 && code <= 0xdbff) {
        if (i + 1 < input.length) {
          const next = input.charCodeAt(i + 1);
          if (next >= 0xdc00 && next <= 0xdfff) {
            i += 2;
            continue;
          }
        }
      } else if (code !== 0xfffd && !(code >= 0xdc00 && code <= 0xdfff) && !isBidiControl(code)) {
        i++;
        continue;
      }
    }

    if (i > safeStart) {
      result.push(input.slice(safeStart, i));
    }

    if (code === 0x1b) {
      i++;
      if (i >= input.length) {
        safeStart = i;
        continue;
      }

      const next = input.charCodeAt(i);

      if (next === 0x5b) {
        const parsed = parseCsiSequence(input, i + 1);
        if (parsed.end !== -1 && parsed.final === "m") {
          if (preserveSgr) {
            result.push(input.slice(i - 1, parsed.end));
          }
          i = parsed.end;
          safeStart = i;
          continue;
        }
        if (parsed.end !== -1) {
          i = parsed.end;
        }
        safeStart = i;
        continue;
      }

      if (next === 0x5d) {
        const end = parseOscSequence(input, i + 1);
        if (end !== -1) {
          const termLen = input.charCodeAt(end - 1) === 0x07 ? 1 : 2;
          const oscContent = input.slice(i + 1, end - termLen);
          if (preserveSgr && isOscSafe(oscContent)) {
            result.push(input.slice(i - 1, end));
            i = end;
            safeStart = i;
            continue;
          }
          i = end;
        }
        safeStart = i;
        continue;
      }

      if (next === 0x50 || next === 0x58 || next === 0x5e || next === 0x5f) {
        i = skipToST(input, i + 1);
        safeStart = i;
        continue;
      }

      // Skip single-character ESC sequence body if printable intermediate
      if (next >= 0x20 && next <= 0x7e) {
        i++;
      }
      safeStart = i;
      continue;
    }

    // Strip C0/C1/DEL/Bidi/lone surrogates cleanly without injecting noise into Arabic text
    i++;
    safeStart = i;
  }

  if (safeStart < input.length) {
    result.push(input.slice(safeStart));
  }

  return result.join("");
}

export function processTerminalLog(log: string, opts?: { preserveSgr?: boolean }): string {
  if (!log) return "";
  if (log.length <= TERMINAL_CHUNK_BYTES) {
    return needsSanitization(log) ? sanitizeTerminalOutput(log, opts) : log;
  }
  const chunks: string[] = [];
  let offset = 0;
  while (offset < log.length) {
    let end = Math.min(log.length, offset + TERMINAL_CHUNK_BYTES);
    // Avoid splitting inside an ESC sequence or UTF-16 surrogate pair
    if (end < log.length) {
      const prevCode = log.charCodeAt(end - 1);
      if (prevCode >= 0xd800 && prevCode <= 0xdbff) {
        end -= 1;
      } else {
        const lastEsc = log.lastIndexOf("\x1b", end - 1);
        if (lastEsc >= offset && end - lastEsc < MAX_CSI_LENGTH) {
          end = lastEsc;
        }
      }
      if (end <= offset) {
        end = Math.min(log.length, offset + TERMINAL_CHUNK_BYTES);
      }
    }
    const piece = log.slice(offset, end);
    chunks.push(needsSanitization(piece) ? sanitizeTerminalOutput(piece, opts) : piece);
    offset = end;
  }
  return chunks.join("");
}

export function sanitizePlainTerminalText(input: string): string {
  return processTerminalLog(input, { preserveSgr: false });
}

export interface AnsiSegment {
  text: string;
  colorClass?: string;
  bold?: boolean;
}

const SGR_COLOR_MAP: Record<number, string> = {
  31: "text-sentinel-danger",
  91: "text-sentinel-danger",
  32: "text-sentinel-success",
  92: "text-sentinel-success",
  33: "text-sentinel-warning",
  93: "text-sentinel-warning",
  34: "text-sentinel-primary",
  94: "text-sentinel-primary",
  35: "text-sentinel-ai",
  95: "text-sentinel-ai",
  36: "text-sentinel-primary",
  96: "text-sentinel-primary",
  90: "text-ink-muted",
};

/**
 * Parse sanitized terminal text with SGR codes into styled React spans (zero HTML injection).
 */
export function parseAnsiSegments(input: string): AnsiSegment[] {
  const clean = processTerminalLog(input, { preserveSgr: true });
  if (!clean) return [];
  if (!clean.includes("\x1b")) {
    return [{ text: clean }];
  }

  const segments: AnsiSegment[] = [];
  let colorClass: string | undefined;
  let bold = false;
  let i = 0;
  let textStart = 0;

  while (i < clean.length) {
    if (clean.charCodeAt(i) === 0x1b && i + 1 < clean.length && clean.charCodeAt(i + 1) === 0x5b) {
      const parsed = parseCsiSequence(clean, i + 2);
      if (parsed.end !== -1 && parsed.final === "m") {
        if (i > textStart) {
          segments.push({ text: clean.slice(textStart, i), colorClass, bold });
        }
        const params = clean
          .slice(i + 2, parsed.end - 1)
          .split(";")
          .map((p) => (p === "" ? 0 : Number.parseInt(p, 10)));
        for (const code of params) {
          if (code === 0) {
            colorClass = undefined;
            bold = false;
          } else if (code === 1) {
            bold = true;
          } else if (code === 22) {
            bold = false;
          } else if (code === 39) {
            colorClass = undefined;
          } else if (code in SGR_COLOR_MAP) {
            colorClass = SGR_COLOR_MAP[code];
          }
        }
        i = parsed.end;
        textStart = i;
        continue;
      }
    }
    i++;
  }

  if (textStart < clean.length) {
    segments.push({ text: clean.slice(textStart), colorClass, bold });
  }
  return segments;
}
