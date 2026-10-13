// Small fetch wrapper: JSON in/out, CSRF header, request ids, readable error messages.

export const REQUEST_ID_HEADER = 'X-Request-Id';

export class ApiError extends Error {
  status: number;
  /** Character offset of a search query syntax error (400 responses from /search). */
  pos?: number;
  /** Id of the failed request, as logged by the backend; quote it when reporting a problem. */
  requestId?: string;
  /** Machine-readable error code from the backend envelope (`conflict`, `invalid_query`, ...). */
  code?: string;
  constructor(status: number, message: string, pos?: number, requestId?: string, code?: string) {
    super(message);
    this.status = status;
    this.pos = pos;
    this.requestId = requestId;
    this.code = code;
  }
}

/** A fresh request id. crypto.randomUUID needs a secure context, which a plain-HTTP LAN install is not. */
export function newRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function' && globalThis.isSecureContext !== false) {
    return crypto.randomUUID().replace(/-/g, '');
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') crypto.getRandomValues(bytes);
  else for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)nf_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

type Params = Record<string, string | number | boolean | null | undefined>;

export function query(params?: Params): string {
  if (!params) return '';
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

/** Human message of an error body: the envelope's `message`, else FastAPI's `detail` (older servers, proxies). */
export function errorMessage(body: any, status: number): string {
  if (typeof body?.message === 'string' && body.message) return body.message;
  const detail = body?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: any) => {
        const loc = Array.isArray(d.loc) ? d.loc.filter((x: any) => x !== 'body').join('.') : '';
        return loc ? `${loc}: ${String(d.msg).replace(/^Value error, /, '')}` : d.msg;
      })
      .join('; ');
  }
  if (status === 502 || status === 503 || status === 504) return 'Backend unavailable. Is the backend running?';
  return `Request failed (${status})`;
}

/** The ApiError for a failed response. Server errors carry a reference so support can find the log lines. */
export function responseError(res: Response, body: any, sentId: string): ApiError {
  const requestId = res.headers.get(REQUEST_ID_HEADER) || sentId;
  let message = errorMessage(body, res.status);
  if (res.status >= 500) message += ` (reference ${requestId})`;
  const pos = typeof body?.pos === 'number' ? body.pos : undefined;
  return new ApiError(res.status, message, pos, requestId, typeof body?.code === 'string' ? body.code : undefined);
}

async function readJson(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

export async function api<T>(path: string, opts: { method?: string; body?: unknown; params?: Params } = {}): Promise<T> {
  const method = opts.method || 'GET';
  const requestId = newRequestId();
  const headers: Record<string, string> = { Accept: 'application/json', [REQUEST_ID_HEADER]: requestId };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken();
  let res: Response;
  try {
    res = await fetch(`/api${path}${query(opts.params)}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Check that it is running.');
  }
  const body = await readJson(res);
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/login')) window.dispatchEvent(new Event('nf:unauthorized'));
    throw responseError(res, body, requestId);
  }
  return body as T;
}

export const get = <T>(path: string, params?: Params) => api<T>(path, { params });
export const post = <T>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body ?? {} });
export const put = <T>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body });
export const patch = <T>(path: string, body: unknown) => api<T>(path, { method: 'PATCH', body });
export const del = <T>(path: string) => api<T>(path, { method: 'DELETE' });

/** Download a binary response (e.g. inventory ZIP) and trigger a browser save. */
export async function downloadBlob(path: string, fallbackName: string): Promise<void> {
  const requestId = newRequestId();
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { Accept: '*/*', [REQUEST_ID_HEADER]: requestId },
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Check that it is running.');
  }
  if (!res.ok) {
    const body = await readJson(res);
    if (res.status === 401) window.dispatchEvent(new Event('nf:unauthorized'));
    throw responseError(res, body, requestId);
  }
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') || '';
  const match = /filename="?([^";]+)"?/i.exec(cd);
  const name = match?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** POST multipart/form-data (do not set Content-Type; the browser adds the boundary). */
export async function postForm<T>(path: string, form: FormData): Promise<T> {
  const requestId = newRequestId();
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-CSRF-Token': csrfToken(), [REQUEST_ID_HEADER]: requestId },
      body: form,
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Check that it is running.');
  }
  const body = await readJson(res);
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event('nf:unauthorized'));
    throw responseError(res, body, requestId);
  }
  return body as T;
}
