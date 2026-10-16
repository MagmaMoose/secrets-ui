import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type SecretVersion, type Store } from "../api";
import { when } from "../format";
import { Dialog } from "./Dialog";
import { Reveal } from "./Reveal";

const STATE: Record<SecretVersion["state"], string> = { enabled: "Enabled", disabled: "Disabled", deleted: "Deleted", destroyed: "Destroyed" };

// Every version of one secret, newest first. A value is fetched only on Reveal, one at a time.
// Restore makes an older version current again, without its value ever reaching the page.
// `enable`: the store enables and disables versions; where it cannot, a readable one is Active.
export function Versions({
  store,
  name,
  expiry,
  enable,
  onRestored,
  onClose,
}: {
  store: Store;
  name: string;
  expiry: boolean;
  enable: boolean;
  onRestored: (version: string) => void;
  onClose: () => void;
}) {
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const [revealed, setRevealed] = useState<{ version: string; value: string } | null>(null);
  const [confirming, setConfirming] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(() => {
    api.versions(store, name).then(setVersions, (err) => setError(err instanceof ApiError ? err.message : "Something went wrong."));
  }, [store, name]);

  useEffect(load, [load]);

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

  async function restore(version: string) {
    setBusy(version);
    setError("");
    try {
      await api.restore(store, name, version);
      setConfirming("");
      setRevealed(null);
      onRestored(version);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally {
      setBusy("");
    }
  }

  return (
    <Dialog title={`Versions of ${name}`} wide onClose={onClose}>
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
                      <span className={v.state === "enabled" ? "status on" : "status off"}>{v.state === "enabled" && !enable ? "Active" : STATE[v.state]}</span>
                    </td>
                    {expiry && <td data-label="Expires">{v.expires ? when(v.expires) : <span className="muted">Never</span>}</td>}
                    <td className="actions-cell">
                      <div className="actions">
                        {confirming === v.version ? (
                          <>
                            <button type="button" className="button small primary" disabled={busy === v.version} onClick={() => void restore(v.version)}>
                              Make current
                            </button>
                            <button type="button" className="button small" onClick={() => setConfirming("")}>
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button
                              type="button"
                              className="button small"
                              disabled={busy === v.version || v.state !== "enabled"}
                              aria-expanded={open}
                              onClick={() => void reveal(v.version)}
                            >
                              {open ? "Hide" : "Reveal"}
                            </button>
                            {!v.current && (
                              <button type="button" className="button small" disabled={busy !== "" || v.state !== "enabled"} onClick={() => setConfirming(v.version)}>
                                Restore
                              </button>
                            )}
                          </>
                        )}
                      </div>
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
