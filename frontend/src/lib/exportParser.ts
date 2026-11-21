/**
 * Parser for Instagram's official "Download your information" export (JSON format).
 * Runs entirely in the browser; nothing here performs network I/O.
 *
 * Defensive by design: size caps, structural validation, and a strict username
 * allow-list (Instagram usernames are [A-Za-z0-9._], max 30), so any value that
 * reaches the UI or a generated link is already known-safe.
 */

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_FILES = 20;
export const MAX_ENTRIES = 250_000;
const USERNAME = /^[A-Za-z0-9._]{1,30}$/;

export class ExportParseError extends Error {
  constructor(
    public readonly code: 'too_large' | 'not_json' | 'unrecognised' | 'too_many_files' | 'too_many_entries' | 'wrong_type',
    message: string,
  ) {
    super(message);
    this.name = 'ExportParseError';
  }
}

export interface ParsedList {
  usernames: string[];
  /** Entries that were present but did not look like a valid username (dropped, never rendered). */
  skipped: number;
}

type Json = unknown;
const isObj = (v: Json): v is Record<string, Json> => typeof v === 'object' && v !== null && !Array.isArray(v);

function usernameFromEntry(entry: Json): string | null {
  if (!isObj(entry)) return null;
  const candidates: string[] = [];
  const list = entry.string_list_data;
  if (Array.isArray(list) && isObj(list[0])) {
    const first = list[0];
    if (typeof first.value === 'string') candidates.push(first.value);
    if (typeof first.href === 'string') {
      const m = /^https:\/\/(?:www\.)?instagram\.com\/(?:_u\/)?([^/?#]+)/i.exec(first.href);
      if (m?.[1]) candidates.push(m[1]);
    }
  }
  if (typeof entry.title === 'string') candidates.push(entry.title);
  const hit = candidates.map((c) => c.trim()).find((c) => USERNAME.test(c));
  return hit ? hit.toLowerCase() : null;
}

function entriesOf(doc: Json): Json[] | null {
  if (Array.isArray(doc)) return doc;
  if (isObj(doc)) {
    const preferred = ['relationships_followers', 'relationships_following', 'relationships_following_hashtags'];
    for (const k of preferred) if (Array.isArray(doc[k])) return doc[k] as Json[];
    const arrays = Object.values(doc).filter(Array.isArray);
    if (arrays.length === 1) return arrays[0] as Json[];
  }
  return null;
}

/** Parse one export file's text. Throws ExportParseError for anything that is not a recognisable relationship list. */
export function parseExportText(text: string): ParsedList {
  if (text.length > MAX_FILE_BYTES) throw new ExportParseError('too_large', 'File is larger than 25 MB.');
  let doc: Json;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new ExportParseError('not_json', 'This is not valid JSON. In the Instagram export, choose the JSON format (not HTML).');
  }
  const entries = entriesOf(doc);
  if (!entries) throw new ExportParseError('unrecognised', 'This does not look like an Instagram followers/following file.');
  if (entries.length > MAX_ENTRIES) throw new ExportParseError('too_many_entries', 'File has too many entries.');
  const out = new Set<string>();
  let skipped = 0;
  for (const e of entries) {
    const u = usernameFromEntry(e);
    if (u) out.add(u);
    else skipped++;
  }
  if (out.size === 0 && entries.length > 0) throw new ExportParseError('unrecognised', 'No usernames could be read from this file.');
  return { usernames: [...out], skipped };
}

/** Parse several files (e.g. followers_1.json, followers_2.json) into one de-duplicated list. */
export async function parseExportFiles(files: File[]): Promise<ParsedList> {
  if (files.length > MAX_FILES) throw new ExportParseError('too_many_files', `Select at most ${MAX_FILES} files.`);
  const all = new Set<string>();
  let skipped = 0;
  for (const f of files) {
    if (f.size > MAX_FILE_BYTES) throw new ExportParseError('too_large', `${safeName(f.name)} is larger than 25 MB.`);
    if (!/\.json$/i.test(f.name)) throw new ExportParseError('wrong_type', `${safeName(f.name)} is not a .json file. Choose the JSON export, not HTML.`);
    const parsed = parseExportText(await f.text());
    parsed.usernames.forEach((u) => all.add(u));
    skipped += parsed.skipped;
  }
  return { usernames: [...all], skipped };
}

function safeName(n: string): string {
  return n.replace(/[^\w.\- ]/g, '').slice(0, 60) || 'file';
}
