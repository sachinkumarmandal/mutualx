import { useId, useRef, useState } from 'react';
import { ExportParseError, parseExportFiles, type ParsedList } from '../lib/exportParser';

interface Props {
  label: string;
  hint: string;
  onParsed: (list: ParsedList | null) => void;
}

export default function DropZone({ label, hint, onParsed }: Props) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [state, setState] = useState<{ count: number; skipped: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handle(files: FileList | File[]) {
    const list = [...files];
    if (!list.length) return;
    try {
      const parsed = await parseExportFiles(list);
      setError(null);
      setState({ count: parsed.usernames.length, skipped: parsed.skipped });
      onParsed(parsed);
    } catch (e) {
      setState(null);
      onParsed(null);
      setError(e instanceof ExportParseError ? e.message : 'Could not read this file.');
    }
  }

  return (
    <div
      className={`rounded-3xl border-2 border-dashed p-5 text-center transition duration-200 ${over ? 'border-emerald-600 bg-emerald-500/10' : state ? 'border-emerald-600/60 bg-white/60' : 'border-navy-800/20 bg-white/40 hover:bg-white/60'}`}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); void handle(e.dataTransfer.files); }}
    >
      <p className="eyebrow">{label}</p>
      {state ? (
        <p className="mt-2 flex items-center justify-center gap-2" data-testid={`loaded-${label.toLowerCase()}`}>
          <span className="grid h-6 w-6 place-items-center rounded-full bg-emerald-500 text-white" aria-hidden="true">✓</span>
          <span className="stat-num text-3xl">{state.count.toLocaleString()}</span>
          <span className="text-sm text-navy-800/70">accounts{state.skipped ? ` · ${state.skipped} skipped` : ''}</span>
        </p>
      ) : (
        <p className="mt-2 text-sm text-navy-800/70">{hint}</p>
      )}
      <label htmlFor={id} className="btn-ghost mt-4 cursor-pointer">{state ? 'Replace file' : 'Choose JSON file(s)'}</label>
      <input
        id={id}
        ref={input}
        type="file"
        accept=".json,application/json"
        multiple
        className="sr-only"
        onChange={(e) => { void handle(e.target.files ?? []); e.target.value = ''; }}
      />
      {error && <p role="alert" className="mt-3 text-sm font-medium text-rose-700">{error}</p>}
    </div>
  );
}
