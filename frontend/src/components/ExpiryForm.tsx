import { useId, useState, type FormEvent } from "react";
import { ApiError, type Secret } from "../api";
import { epochToLocalInput, localInputToIso } from "../format";
import { Dialog } from "./Dialog";

export function ExpiryForm({
  secret,
  save,
  onDone,
  onClose,
}: {
  secret: Secret;
  save: (expires: string | null) => Promise<unknown>;
  onDone: () => void;
  onClose: () => void;
}) {
  const [never, setNever] = useState(!secret.expires);
  const [value, setValue] = useState(epochToLocalInput(secret.expires));
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const id = useId();

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await save(never ? null : localInputToIso(value));
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={`Expiry of ${secret.name}`} onClose={onClose}>
      <form className="dialog-body form" onSubmit={onSubmit}>
        <label className="check">
          <input type="checkbox" checked={never} onChange={(e) => setNever(e.target.checked)} />
          <span>No expiry</span>
        </label>
        <div className="field">
          <label htmlFor={`${id}-expires`}>Expires</label>
          <input
            id={`${id}-expires`}
            type="datetime-local"
            value={value}
            disabled={never}
            required={!never}
            data-autofocus
            aria-describedby={`${id}-hint`}
            onChange={(e) => setValue(e.target.value)}
          />
          <small id={`${id}-hint`} className="hint">
            Applies to the current version. Key Vault still returns an expired value; the date is for people and alerts.
          </small>
        </div>
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        <footer className="dialog-footer">
          <button type="button" className="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="button primary" disabled={busy || (!never && !value)}>
            {busy ? "Saving…" : "Save"}
          </button>
        </footer>
      </form>
    </Dialog>
  );
}
