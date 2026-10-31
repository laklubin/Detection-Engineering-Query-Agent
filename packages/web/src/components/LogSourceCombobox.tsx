import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import type { CatalogLogSource } from '../lib/api.js';

/**
 * Searchable log-source selector.
 *
 * Only ids that exist in the backend-provided catalogue can be selected, which
 * keeps the request body inside the server-side allowlist.
 */
export function LogSourceCombobox({
  sources,
  value,
  onChange,
  inputRef,
  disabled,
}: {
  sources: readonly CatalogLogSource[];
  value: string;
  onChange: (id: string) => void;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  disabled?: boolean;
}): ReactNode {
  const listId = useId();
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  const selected = useMemo(() => sources.find((s) => s.id === value), [sources, value]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle.length === 0) return sources.slice(0, 50);
    return sources
      .filter(
        (source) =>
          source.name.toLowerCase().includes(needle) ||
          source.id.includes(needle.replace(/\s+/g, '_')) ||
          source.telemetry.includes(needle) ||
          source.keywords.some((keyword) => keyword.toLowerCase().includes(needle)),
      )
      .slice(0, 50);
  }, [sources, query]);

  useEffect(() => {
    function onPointerDown(event: MouseEvent): void {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, []);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  function commit(source: CatalogLogSource): void {
    onChange(source.id);
    setQuery('');
    setOpen(false);
  }

  return (
    <div ref={containerRef} className="relative">
      <label htmlFor={`${listId}-input`} className="mb-1.5 block text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]">
        Log source
      </label>
      <div className="flex gap-2">
        <input
          id={`${listId}-input`}
          ref={inputRef}
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          autoComplete="off"
          disabled={disabled}
          className="dfai-input"
          placeholder={selected ? selected.name : 'Search log sources, e.g. 4625, sysmon, cloudtrail'}
          value={open ? query : (selected?.name ?? '')}
          onFocus={() => setOpen(true)}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
          }}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              setOpen(true);
              setActiveIndex((index) => Math.min(index + 1, filtered.length - 1));
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              setActiveIndex((index) => Math.max(index - 1, 0));
            } else if (event.key === 'Enter' && open) {
              const choice = filtered[activeIndex];
              if (choice) {
                event.preventDefault();
                commit(choice);
              }
            } else if (event.key === 'Escape') {
              setOpen(false);
            }
          }}
        />
        {value ? (
          <button
            type="button"
            className="dfai-btn dfai-btn-ghost shrink-0 px-3 text-xs"
            onClick={() => {
              onChange('');
              setQuery('');
            }}
            aria-label="Remove the selected log source"
          >
            Clear
          </button>
        ) : null}
      </div>

      {open ? (
        <ul
          id={listId}
          role="listbox"
          className="absolute z-20 mt-1.5 max-h-72 w-full overflow-auto rounded-lg border border-[var(--color-forge-border-strong)] bg-[var(--color-forge-panel)] shadow-2xl"
        >
          {filtered.length === 0 ? (
            <li className="px-3 py-2.5 text-sm text-[var(--color-forge-muted)]">
              No matching log source. Detection queries are only generated for documented telemetry.
            </li>
          ) : (
            filtered.map((source, index) => (
              <li
                key={source.id}
                role="option"
                aria-selected={source.id === value}
                className={`cursor-pointer px-3 py-2 text-sm ${
                  index === activeIndex ? 'bg-[var(--color-forge-accent)]/12' : ''
                }`}
                onMouseEnter={() => setActiveIndex(index)}
                onMouseDown={(event) => {
                  event.preventDefault();
                  commit(source);
                }}
              >
                <span className="block font-medium text-[var(--color-forge-text)]">{source.name}</span>
                <span className="block text-[11px] text-[var(--color-forge-muted)]">
                  {source.vendorId} · telemetry: {source.telemetry}
                </span>
              </li>
            ))
          )}
        </ul>
      ) : null}
    </div>
  );
}
