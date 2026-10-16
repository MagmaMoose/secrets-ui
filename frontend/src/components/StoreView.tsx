import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, type AuditEvent, type DeletedSecret, type Feature, type ProviderInfo, type Secret, type Store } from "../api";
import { expiryState, fromNow, when } from "../format";
import { Confirm } from "./Dialog";
import { ExpiryForm } from "./ExpiryForm";
import { Menu, type MenuItem } from "./Menu";
import { Reveal } from "./Reveal";
import { SecretForm } from "./SecretForm";
import { Versions } from "./Versions";

type Notify = (message: string, kind?: "info" | "error") => void;

const TAB_LABEL = { secrets: "Secrets", deleted: "Deleted", audit: "Audit log" };

type Modal =
  | { kind: "create" }
  | { kind: "version"; secret: Secret }
  | { kind: "versions"; secret: Secret }
  | { kind: "expiry"; secret: Secret }
  | { kind: "disable"; secret: Secret }
  | { kind: "delete"; secret: Secret }
  | null;

function errorText(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong.";
}

function Expiry({ epoch }: { epoch: number | null }) {
  const state = expiryState(epoch);
  if (state === "none") return <span className="muted">Never</span>;
  return (
    <span className={`expiry ${state}`} title={when(epoch, true)}>
      {state === "expired" ? "Expired " : ""}
      {when(epoch)}
      {state === "soon" && <span className="muted"> · {fromNow(epoch!)}</span>}
    </span>
  );
}

export function StoreView({ store, provider, notify }: { store: Store; provider: ProviderInfo; notify: Notify }) {
  const has = useCallback((feature: Feature) => provider.features.includes(feature), [provider]);
  const [tab, setTab] = useState<"secrets" | "deleted" | "audit">("secrets");
  const [secrets, setSecrets] = useState<Secret[] | null>(null);
  const [deleted, setDeleted] = useState<DeletedSecret[] | null>(null);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [revealed, setRevealed] = useState<{ name: string; value: string } | null>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError("");
    try {
      if (tab === "secrets") setSecrets(await api.secrets(store));
      else if (tab === "deleted") setDeleted(await api.deleted(store));
      else setEvents(await api.audit(store));
    } catch (err) {
      setError(errorText(err));
    }
  }, [tab, store]);

  useEffect(() => {
    setSecrets(null);
    setDeleted(null);
    setEvents(null);
    setRevealed(null);
    setFilter("");
    setTab("secrets");
  }, [store]);

  useEffect(() => {
    setRevealed(null);
    void load();
  }, [load]);

  const hide = useCallback(() => setRevealed(null), []);

  const rows = useMemo(() => {
    const list = tab === "secrets" ? secrets : deleted;
    const needle = filter.trim().toLowerCase();
    return list?.filter((s) => !needle || s.name.toLowerCase().includes(needle)) ?? null;
  }, [tab, secrets, deleted, filter]);

  const auditRows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return events?.filter((e) => !needle || `${e.secret} ${e.caller} ${e.operation}`.toLowerCase().includes(needle)) ?? null;
  }, [events, filter]);

  async function act(name: string, action: () => Promise<unknown>, done: string) {
    setBusy(name);
    try {
      await action();
      notify(done);
      // The other tabs' lists are stale now too; they reload when opened.
      if (tab === "secrets") setDeleted(null);
      else setSecrets(null);
      setEvents(null);
      await load();
    } catch (err) {
      notify(errorText(err), "error");
    } finally {
      setBusy(null);
      setModal(null);
    }
  }

  async function reveal(name: string) {
    if (revealed?.name === name) return setRevealed(null);
    setBusy(name);
    try {
      setRevealed({ name, value: await api.reveal(store, name) });
    } catch (err) {
      notify(errorText(err), "error");
    } finally {
      setBusy(null);
    }
  }

  function menu(secret: Secret): MenuItem[] {
    const items: MenuItem[] = [{ label: "New version", onSelect: () => setModal({ kind: "version", secret }) }];
    if (has("versions")) items.push({ label: "Versions", onSelect: () => setModal({ kind: "versions", secret }) });
    if (has("expiry")) items.push({ label: "Set expiry", onSelect: () => setModal({ kind: "expiry", secret }) });
    if (has("enable")) {
      items.push({
        label: secret.enabled ? "Disable" : "Enable",
        onSelect: () =>
          secret.enabled
            ? setModal({ kind: "disable", secret })
            : void act(secret.name, () => api.update(store, secret.name, { enabled: true }), `${secret.name} enabled.`),
      });
    }
    items.push({ label: "Delete", danger: true, onSelect: () => setModal({ kind: "delete", secret }) });
    return items;
  }

  const columns = 3 + Number(has("enable")) + Number(has("expiry")) + Number(has("content_type"));
  const tabs = (["secrets", "deleted", "audit"] as const).filter((t) => t === "secrets" || (t === "deleted" ? has("recover") : store.audit));

  return (
    <section className="vault" aria-labelledby="store-title">
      <div className="vault-head">
        <div>
          <h1 id="store-title">{store.label}</h1>
          <p className="muted small mono">{store.location}</p>
        </div>
        <button type="button" className="button primary" onClick={() => setModal({ kind: "create" })}>
          New secret
        </button>
      </div>

      <div className="toolbar">
        <div className="tabs" role="tablist" aria-label="Secrets or deleted secrets">
          {tabs.map((t) => {
            const list = t === "secrets" ? secrets : t === "deleted" ? deleted : events;
            return (
              <button key={t} type="button" role="tab" aria-selected={tab === t} className="tab" onClick={() => setTab(t)}>
                {TAB_LABEL[t]}
                {list && <span className="count">{list.length}</span>}
              </button>
            );
          })}
        </div>
        <input
          className="filter"
          type="search"
          placeholder={tab === "audit" ? "Filter by secret or person" : "Filter by name"}
          aria-label="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button type="button" className="button" onClick={() => void load()}>
          Refresh
        </button>
      </div>

      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {!error && (tab === "audit" ? auditRows : rows) === null && <p className="muted">Loading…</p>}
      {tab !== "audit" && rows && rows.length === 0 && (
        <p className="empty">{filter ? "Nothing matches that filter." : tab === "secrets" ? "No secrets here yet." : "Nothing deleted."}</p>
      )}

      {tab === "audit" && auditRows && (
        <>
          <p className="muted small">What the vault itself recorded in the last 30 days, newest first. Entries arrive a few minutes late.</p>
          {auditRows.length === 0 ? (
            <p className="empty">{filter ? "Nothing matches that filter." : "Nothing recorded."}</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Who</th>
                  <th scope="col">Operation</th>
                  <th scope="col">Secret</th>
                  <th scope="col">Result</th>
                  <th scope="col">From</th>
                </tr>
              </thead>
              <tbody>
                {auditRows.map((e, i) => (
                  <tr key={i}>
                    <td data-label="Time">{when(e.time, true)}</td>
                    <td data-label="Who" className="name">
                      {e.caller || "—"}
                    </td>
                    <td data-label="Operation" className="mono">
                      {e.operation}
                    </td>
                    <td data-label="Secret" className="mono">
                      {e.secret || "—"}
                    </td>
                    <td data-label="Result">
                      <span className={e.result === "OK" ? "status on" : "status off"}>{e.result || "—"}</span>
                    </td>
                    <td data-label="From" className="muted mono">
                      {e.ip || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "secrets" && rows && rows.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              {has("enable") && <th scope="col">Status</th>}
              {has("expiry") && <th scope="col">Expires</th>}
              <th scope="col">Updated</th>
              {has("content_type") && <th scope="col">Content type</th>}
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(rows as Secret[]).map((secret) => {
              const open = revealed?.name === secret.name;
              const locked = secret.managed;
              return [
                <tr key={secret.name} className={open ? "open" : undefined}>
                  <td data-label="Name" className="name mono">
                    {secret.name}
                    {locked && <span className="badge">certificate</span>}
                  </td>
                  {has("enable") && (
                    <td data-label="Status">
                      <span className={secret.enabled ? "status on" : "status off"}>{secret.enabled ? "Enabled" : "Disabled"}</span>
                    </td>
                  )}
                  {has("expiry") && (
                    <td data-label="Expires">
                      <Expiry epoch={secret.expires} />
                    </td>
                  )}
                  <td data-label="Updated" title={when(secret.updated, true)}>
                    {when(secret.updated)}
                  </td>
                  {has("content_type") && (
                    <td data-label="Content type" className="muted">
                      {secret.content_type || "—"}
                    </td>
                  )}
                  <td className="actions-cell">
                    <div className="actions">
                      <button type="button" className="button small" disabled={busy === secret.name} onClick={() => void reveal(secret.name)} aria-expanded={open}>
                        {open ? "Hide" : "Reveal"}
                      </button>
                      <Menu label="More" disabled={busy === secret.name || locked} items={menu(secret)} />
                    </div>
                  </td>
                </tr>,
                open && (
                  <tr key={`${secret.name}-value`} className="reveal-row">
                    <td colSpan={columns}>
                      <Reveal name={secret.name} value={revealed.value} onHide={hide} />
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
      )}

      {tab === "deleted" && rows && rows.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Deleted</th>
              <th scope="col">Purged by the store</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(rows as DeletedSecret[]).map((secret) => (
              <tr key={secret.name}>
                <td data-label="Name" className="name mono">
                  {secret.name}
                </td>
                <td data-label="Deleted">{when(secret.deleted, true)}</td>
                <td data-label="Purged">{when(secret.purge_at)}</td>
                <td className="actions-cell">
                  <button
                    type="button"
                    className="button small"
                    disabled={busy === secret.name}
                    onClick={() => void act(secret.name, () => api.recover(store, secret.name), `${secret.name} recovered.`)}
                  >
                    Recover
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {modal?.kind === "create" && (
        <SecretForm
          title="New secret"
          namePattern={provider.name_pattern}
          nameHint={provider.name_hint}
          valueHint={provider.value_hint}
          features={provider.features}
          submit={(input) => api.create(store, input)}
          onDone={(name) => {
            setModal(null);
            notify(`${name} created.`);
            void load();
          }}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.kind === "version" && (
        <SecretForm
          title={`New version of ${modal.secret.name}`}
          name={modal.secret.name}
          namePattern={provider.name_pattern}
          nameHint={provider.name_hint}
          valueHint={provider.value_hint}
          features={provider.features}
          contentType={modal.secret.content_type}
          submit={({ value, content_type, expires }) => api.newVersion(store, modal.secret.name, { value, content_type, expires })}
          onDone={(name) => {
            setModal(null);
            setRevealed(null);
            notify(`New version of ${name} saved.`);
            void load();
          }}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.kind === "versions" && <Versions store={store} name={modal.secret.name} expiry={has("expiry")} enable={has("enable")} onClose={() => setModal(null)} />}
      {modal?.kind === "expiry" && (
        <ExpiryForm
          secret={modal.secret}
          save={(expires) => api.update(store, modal.secret.name, { expires })}
          onDone={() => {
            setModal(null);
            notify(`Expiry of ${modal.secret.name} saved.`);
            void load();
          }}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.kind === "disable" && (
        <Confirm
          title={`Disable ${modal.secret.name}?`}
          action="Disable"
          danger
          busy={busy === modal.secret.name}
          onClose={() => setModal(null)}
          onConfirm={() => void act(modal.secret.name, () => api.update(store, modal.secret.name, { enabled: false }), `${modal.secret.name} disabled.`)}
        >
          <p>Anything that reads this secret gets an error until it is enabled again.</p>
        </Confirm>
      )}
      {modal?.kind === "delete" && (
        <Confirm
          title={`Delete ${modal.secret.name}?`}
          action="Delete"
          danger
          busy={busy === modal.secret.name}
          onClose={() => setModal(null)}
          onConfirm={() =>
            void act(modal.secret.name, () => api.remove(store, modal.secret.name), `${modal.secret.name} deleted.${has("recover") ? " Recover it from Deleted." : ""}`)
          }
        >
          {has("recover") ? (
            <p>
              The secret moves to Deleted, where it can be recovered
              {modal.secret.recoverable_days ? ` for ${modal.secret.recoverable_days} days` : ""}. Its name stays taken until then.
            </p>
          ) : (
            <p>The secret is deleted.</p>
          )}
        </Confirm>
      )}
    </section>
  );
}
