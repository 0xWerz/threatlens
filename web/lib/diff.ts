import { AddedLine } from "./types";

const HUNK_HEADER = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/;

export function parseAddedLines(diffText: string): AddedLine[] {
  const lines = diffText.split(/\r?\n/);
  const added: AddedLine[] = [];

  let currentFile: string | null = null;
  let newLineNumber = 0;
  let inHunk = false;

  for (const rawLine of lines) {
    if (rawLine.startsWith("+++ ")) {
      const parsed = parseNewFilePath(rawLine);
      currentFile = parsed;
      inHunk = false;
      continue;
    }

    const hunkMatch = rawLine.match(HUNK_HEADER);
    if (hunkMatch) {
      newLineNumber = Number.parseInt(hunkMatch[1], 10);
      inHunk = true;
      continue;
    }

    if (!inHunk || !currentFile) {
      continue;
    }

    if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
      added.push({
        filePath: currentFile,
        line: newLineNumber,
        text: rawLine.slice(1),
      });
      newLineNumber += 1;
      continue;
    }

    if (rawLine.startsWith(" ")) {
      newLineNumber += 1;
      continue;
    }

    if (rawLine.startsWith("-")) {
      continue;
    }
  }

  return added;
}

function parseNewFilePath(rawLine: string): string | null {
  const value = rawLine.slice(4).trim();
  if (value === "/dev/null") {
    return null;
  }

  if (value.startsWith("b/")) {
    return value.slice(2);
  }

  return value;
}
