import { useEffect, useState } from "react";
import { api, ApiError, type Store } from "../api";
import { Dialog } from "./Dialog";

// An ExternalSecret that reads this secret into a Kubernetes Secret, and the kustomization that
// includes it. Built from names only; no value is fetched for it.
export function KustomizeExample({ store, name, onClose }: { store: Store; name: string; onClose: () => void }) {
  const [example, setExample] = useState<{ secret_store: string; files: Record<string, string> } | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");

  useEffect(() => {
    api.externalSecret(store, name).then(setExample, (err) => setError(err instanceof ApiError ? err.message : "Something went wrong."));
  }, [store, name]);

  async function copy(file: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(file);
    } catch {
      setCopied("");
    }
  }

  return (
    <Dialog title={`Kustomize example for ${name}`} wide onClose={onClose}>
      <div className="dialog-body form">
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        {!error && !example && <p className="muted">Loading…</p>}
        {example && (
          <>
            <p className="muted">
              For the External Secrets Operator. It reads through <span className="mono">{example.secret_store}</span>, which has to exist on the
              cluster; change the names to fit your app.
            </p>
            {Object.entries(example.files).map(([file, text]) => (
              <div key={file} className="field">
                <div className="file-head">
                  <span className="mono small">{file}</span>
                  <button type="button" className="button small" onClick={() => void copy(file, text)}>
                    {copied === file ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="mono reveal-value">{text}</pre>
              </div>
            ))}
          </>
        )}
      </div>
    </Dialog>
  );
}
