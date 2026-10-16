import { useEffect, useState } from "react";

const SHOW_SECONDS = 60;

// A revealed value lives in this component's state only: never in storage, the URL or a log,
// and it is gone after a minute, on Hide, or when the row unmounts.
export function Reveal({ name, value, onHide }: { name: string; value: string; onHide: () => void }) {
  const [left, setLeft] = useState(SHOW_SECONDS);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(() => setLeft((s) => s - 1), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (left <= 0) onHide();
  }, [left, onHide]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="reveal" role="region" aria-label={`Value of ${name}`}>
      <pre className="mono reveal-value">{value}</pre>
      <div className="reveal-actions">
        <button type="button" className="button small" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" className="button small" onClick={onHide}>
          Hide
        </button>
        <span className="muted">Hides in {left}s</span>
      </div>
    </div>
  );
}
