import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type SecretVersion, type Store } from "../api";
import { when } from "../format";
import { Dialog } from "./Dialog";
import { Reveal } from "./Reveal";

const STATE: Record<SecretVersion["state"], string> = { enabled: "Enabled", disabled: "Disabled", deleted: "Deleted", destroyed: "Destroyed" };

// Every version of one secret, newest first. A value is fetched only on Reveal, one at a time.
export function Versions({ store, name, expiry, onClose }: { store: Store; name: string; expiry: boolean; onClose: () => void }) {
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const [revealed, setRevealed] = useState<{ version: string; value: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    api.versions(store, name).then(setVersions, (err) => setError(err instanceof ApiError ? err.message : "Something went wrong."));
  }, [store, name]);

  const hide = useCallback(() => setRevealed(null), []);

  async function reveal(version: string) {
    if (revealed?.version === version) return setRevealed(null);
    setBusy(version);
    setError("");
    try {
      setRevealed({ version, value: await api.revealVersion(store, name, version) });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally {
      setBusy("");
    }
  }

  return (
    <Dialog title={`Versions of ${name}`} onClose={onClose}>
      <div className="dialog-body versions">
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        {!error && versions === null && <p className="muted">Loading…</p>}
        {versions && (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Version</th>
                <th scope="col">Created</th>
                <th scope="col">Status</th>
                {expiry && <th scope="col">Expires</th>}
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => {
                const open = revealed?.version === v.version;
                return [
                  <tr key={v.version} className={open ? "open" : undefined}>
                    <td data-label="Version" className="mono" title={v.version}>
                      {v.version.slice(0, 8)}
                      {v.current && <span className="badge">current</span>}
                    </td>
                    <td data-label="Created" title={when(v.created, true)}>
                      {when(v.created)}
                    </td>
                    <td data-label="Status">
                      <span className={v.state === "enabled" ? "status on" : "status off"}>{STATE[v.state]}</span>
                    </td>
                    {expiry && <td data-label="Expires">{v.expires ? when(v.expires) : <span className="muted">Never</span>}</td>}
                    <td className="actions-cell">
                      <button
                        type="button"
                        className="button small"
                        disabled={busy === v.version || v.state !== "enabled"}
                        aria-expanded={open}
                        onClick={() => void reveal(v.version)}
                      >
                        {open ? "Hide" : "Reveal"}
                      </button>
                    </td>
                  </tr>,
                  open && (
                    <tr key={`${v.version}-value`} className="reveal-row">
                      <td colSpan={4 + Number(expiry)}>
                        <Reveal name={`${name}, version ${v.version}`} value={revealed.value} onHide={hide} />
                      </td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        )}
      </div>
    </Dialog>
  );
}
