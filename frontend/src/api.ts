// The backend's JSON API. Same origin, the session cookie rides along, and every write
// carries the session's CSRF token. Secret values only ever travel in request bodies.
// A store is one place secrets live (an Azure key vault, a folder in a HashiCorp Vault KV mount);
// its provider's features say which controls apply.

export type Feature = "expiry" | "enable" | "content_type" | "recover" | "versions";

export type ProviderInfo = { id: string; label: string; features: Feature[]; name_pattern: string; name_hint: string; value_hint: string };

// `label` is the operator's name for the store, or the store's own name. `audit`: the store's
// audit log can be shown.
export type Store = { provider: string; name: string; label: string; location: string; audit: boolean };

export type Me = {
  name: string;
  upn: string;
  csrf: string;
  expires: number;
  version: string;
  providers: ProviderInfo[];
  stores: Store[];
};

export type Secret = {
  name: string;
  enabled: boolean;
  expires: number | null;
  not_before: number | null;
  created: number | null;
  updated: number | null;
  content_type: string | null;
  managed: boolean;
  recoverable_days: number | null;
};

export type DeletedSecret = Secret & { deleted: number | null; purge_at: number | null };

// One entry in a store's own audit log; `secret` is empty for an operation on the store itself.
// `caller_id` is set when the caller is shown by name.
export type AuditEvent = { time: number | null; operation: string; result: string; caller: string; caller_id?: string; ip: string; secret: string };

export type SecretVersion = {
  version: string;
  created: number | null;
  updated: number | null;
  expires: number | null;
  state: "enabled" | "disabled" | "deleted" | "destroyed";
  current: boolean;
};

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const MESSAGES: Record<string, string> = {
  signed_out: "Your session has ended. Sign in again.",
  csrf: "This page is out of date. Reload it and try again.",
  store_not_allowed: "Your account has no role for this store.",
  exists: "A secret with this name already exists. Add a new version instead.",
  sign_in_unavailable: "Sign-in did not answer. Try again in a moment.",
  invalid_request: "Some fields are not valid.",
};

let csrf = "";
let onSignedOut: () => void = () => {};

export function configure(token: string, signedOut: () => void) {
  csrf = token;
  onSignedOut = signedOut;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "network", "The server could not be reached.");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const code = String(data.error ?? response.status);
    if (response.status === 401) onSignedOut();
    throw new ApiError(response.status, code, data.message ?? MESSAGES[code] ?? `Request failed (${response.status}).`);
  }
  return data as T;
}

const at = (store: Store) => `/api/stores/${encodeURIComponent(store.provider)}/${encodeURIComponent(store.name)}`;
// A Vault secret's name is a path. Its slashes stay slashes: proxies refuse an encoded one (%2F).
const path = (name: string) => name.split("/").map(encodeURIComponent).join("/");
const one = (store: Store, name: string) => `${at(store)}/secrets/${path(name)}`;

export type SecretBody = { value: string; content_type?: string; expires?: string | null };

export const api = {
  me: () => request<Me>("GET", "/api/me"),
  signInProvider: () => request<{ id: "entra" | "google"; name: string }>("GET", "/auth/provider"),
  logout: () => request<unknown>("POST", "/auth/logout"),
  secrets: (store: Store) => request<{ secrets: Secret[] }>("GET", `${at(store)}/secrets`).then((r) => r.secrets),
  deleted: (store: Store) => request<{ secrets: DeletedSecret[] }>("GET", `${at(store)}/deleted`).then((r) => r.secrets),
  create: (store: Store, body: SecretBody & { name: string }) => request<unknown>("POST", `${at(store)}/secrets`, body),
  newVersion: (store: Store, name: string, body: SecretBody) => request<unknown>("POST", `${one(store, name)}/versions`, body),
  update: (store: Store, name: string, body: { enabled?: boolean; expires?: string | null; content_type?: string | null }) =>
    request<{ secret: Secret }>("PATCH", one(store, name), body),
  remove: (store: Store, name: string) => request<unknown>("DELETE", one(store, name)),
  recover: (store: Store, name: string) => request<unknown>("POST", `${at(store)}/deleted/${path(name)}/recover`),
  reveal: (store: Store, name: string) => request<{ value: string }>("POST", `${one(store, name)}/reveal`).then((r) => r.value),
  audit: (store: Store) => request<{ events: AuditEvent[] }>("GET", `${at(store)}/audit`).then((r) => r.events),
  versions: (store: Store, name: string) => request<{ versions: SecretVersion[] }>("GET", `${one(store, name)}/versions`).then((r) => r.versions),
  externalSecret: (store: Store, name: string) =>
    request<{ secret_store: string; files: Record<string, string> }>("GET", `${one(store, name)}/external-secret`),
  restore: (store: Store, name: string, version: string) => request<unknown>("POST", `${one(store, name)}/restore`, { version }),
  revealVersion: (store: Store, name: string, version: string) =>
    request<{ value: string }>("POST", `${one(store, name)}/reveal`, { version }).then((r) => r.value),
};
