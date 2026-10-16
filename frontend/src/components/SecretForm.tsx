import { useId, useState, type FormEvent } from "react";
import { ApiError, type Feature } from "../api";
import { localInputToIso } from "../format";
import { Dialog } from "./Dialog";

export type SecretInput = { name: string; value: string; content_type?: string; expires: string | null };

// One form for a new secret and for a new version of an existing one (`name` fixed).
export function SecretForm({
  title,
  name,
  namePattern,
  nameHint,
  features,
  contentType,
  submit,
  onDone,
  onClose,
}: {
  title: string;
  name?: string;
  namePattern: string;
  nameHint: string;
  features: Feature[];
  contentType?: string | null;
  submit: (input: SecretInput) => Promise<unknown>;
  onDone: (name: string) => void;
  onClose: () => void;
}) {
  const [secretName, setSecretName] = useState(name ?? "");
  const [value, setValue] = useState("");
  const [type, setType] = useState(contentType ?? "");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const nameValid = new RegExp(namePattern).test(secretName);
  const id = useId();

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!nameValid || !value) return;
    setBusy(true);
    setError("");
    try {
      await submit({ name: secretName, value, content_type: type || undefined, expires: localInputToIso(expires) });
      setValue("");
      onDone(secretName);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={title} onClose={onClose}>
      <form className="dialog-body form" onSubmit={onSubmit} autoComplete="off">
        {name === undefined && (
          <div className="field">
            <label htmlFor={`${id}-name`}>Name</label>
            <input
              id={`${id}-name`}
              value={secretName}
              onChange={(e) => setSecretName(e.target.value)}
              required
              data-autofocus
              spellCheck={false}
              placeholder="database-password"
              aria-describedby={`${id}-name-hint`}
              aria-invalid={secretName !== "" && !nameValid}
            />
            <small id={`${id}-name-hint`} className={secretName !== "" && !nameValid ? "hint error" : "hint"}>
              {nameHint}
            </small>
          </div>
        )}
        <div className="field">
          <label htmlFor={`${id}-value`}>Value</label>
          <textarea
            id={`${id}-value`}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
            data-autofocus={name !== undefined ? true : undefined}
            rows={4}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            aria-describedby={`${id}-value-hint`}
            className="mono"
          />
          <small id={`${id}-value-hint`} className="hint">
            Stored as a new version. Up to 25 KB.
          </small>
        </div>
        {(features.includes("content_type") || features.includes("expiry")) && (
          <div className="form-row">
            {features.includes("content_type") && (
              <div className="field">
                <label htmlFor={`${id}-type`}>Content type</label>
                <input id={`${id}-type`} value={type} onChange={(e) => setType(e.target.value)} maxLength={255} placeholder="optional" />
              </div>
            )}
            {features.includes("expiry") && (
              <div className="field">
                <label htmlFor={`${id}-expires`}>Expires</label>
                <input id={`${id}-expires`} type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
              </div>
            )}
          </div>
        )}
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        <footer className="dialog-footer">
          <button type="button" className="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="button primary" disabled={busy || !nameValid || !value}>
            {busy ? "Saving…" : "Save"}
          </button>
        </footer>
      </form>
    </Dialog>
  );
}
