import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, configure, type Me, type Store } from "./api";
import { StoreView } from "./components/StoreView";

type Toast = { id: number; message: string; kind: "info" | "error" };

// The store in view lives in the hash (#/<provider>/<store>): names, never a value.
function routeFromHash(): string {
  return decodeURIComponent(window.location.hash.replace(/^#\/?/, ""));
}

const routeOf = (store: Store) => `${store.provider}/${store.name}`;

// The callback sends a sign-in error back as ?auth_error=; show it once and drop it from the URL.
function takeAuthError(): string {
  const params = new URLSearchParams(window.location.search);
  const error = params.get("auth_error") ?? "";
  if (params.has("auth_error")) window.history.replaceState(null, "", window.location.pathname + window.location.hash);
  return error;
}

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [state, setState] = useState<"loading" | "signed-out" | "ready" | "ended">("loading");
  const [authError] = useState(takeAuthError);
  const [route, setRoute] = useState(routeFromHash);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextToast = useRef(0);

  const notify = useCallback((message: string, kind: "info" | "error" = "info") => {
    const id = ++nextToast.current;
    setToasts((t) => [...t, { id, message, kind }]);
    if (kind === "info") window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);

  useEffect(() => {
    api
      .me()
      .then((data) => {
        configure(data.csrf, () => setState("ended"));
        setMe(data);
        setState("ready");
      })
      .catch((err) => setState(err instanceof ApiError && err.status === 401 ? "signed-out" : "ended"));
  }, []);

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const current = me?.stores.find((s) => routeOf(s) === route);

  useEffect(() => {
    if (me && me.stores.length > 0 && !current) window.location.hash = `/${routeOf(me.stores[0])}`;
  }, [me, current]);

  async function signOut() {
    try {
      await api.logout();
    } finally {
      setMe(null);
      setState("signed-out");
    }
  }

  if (state === "loading") return <main className="center muted">Loading…</main>;

  if (state === "signed-out" || state === "ended" || !me) {
    return (
      <main className="center">
        <div className="card sign-in">
          <Logo />
          <h1>Secrets UI</h1>
          <p className="muted">
            {state === "ended" ? "Your session has ended." : "Sign in with your Microsoft work account to manage the secrets your roles give you."}
          </p>
          {authError && (
            <p className="notice error" role="alert">
              {authError}
            </p>
          )}
          <a className="button primary wide" href="/auth/login">
            Sign in with Microsoft
          </a>
        </div>
      </main>
    );
  }

  const provider = current && me.providers.find((p) => p.id === current.provider);

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="#/">
          <Logo />
          <span>Secrets UI</span>
        </a>
        <div className="who">
          <span title={me.upn}>{me.name || me.upn}</span>
          <button type="button" className="button small" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>

      {me.stores.length === 0 ? (
        <main className="center">
          <div className="card">
            <h1>Nothing to manage yet</h1>
            <p className="muted">You signed in, but none of your roles names a store this app manages. Ask for the group of the vault you need.</p>
          </div>
        </main>
      ) : (
        <div className="layout">
          <nav className="vaults" aria-label="Stores">
            <select className="vault-select" aria-label="Store" value={route} onChange={(e) => (window.location.hash = `/${e.target.value}`)}>
              {me.providers.map((p) => (
                <optgroup key={p.id} label={p.label}>
                  {me.stores
                    .filter((s) => s.provider === p.id)
                    .map((s) => (
                      <option key={routeOf(s)} value={routeOf(s)}>
                        {s.label}
                      </option>
                    ))}
                </optgroup>
              ))}
            </select>
            {me.providers.map((p) => {
              const stores = me.stores.filter((s) => s.provider === p.id);
              if (stores.length === 0) return null;
              return (
                <div key={p.id} className="nav-group">
                  <h2 className="nav-title">{p.label}</h2>
                  <ul>
                    {stores.map((s) => (
                      <li key={routeOf(s)}>
                        <a
                          href={`#/${routeOf(s)}`}
                          aria-current={routeOf(s) === route ? "page" : undefined}
                          title={s.label === s.name ? undefined : s.name}
                        >
                          {s.label}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
            <p className="muted small version">{me.version}</p>
          </nav>
          <main className="content">{current && provider && <StoreView store={current} provider={provider} notify={notify} />}</main>
        </div>
      )}

      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            <span>{t.message}</span>
            <button type="button" className="icon-button" aria-label="Dismiss" onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}>
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function Logo() {
  return (
    <svg className="logo" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" />
      <circle cx="12" cy="16" r="5" />
      <path d="M17 16h9m-3 0v4m-4-4v3" />
    </svg>
  );
}
