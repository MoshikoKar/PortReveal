// Small fetch wrapper: JSON in/out, CSRF header, readable error messages.

export class ApiError extends Error {
  status: number;
  /** Character offset of a search query syntax error (400 responses from /search). */
  pos?: number;
  constructor(status: number, message: string, pos?: number) {
    super(message);
    this.status = status;
    this.pos = pos;
  }
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

function errorMessage(body: any, status: number): string {
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

export async function api<T>(path: string, opts: { method?: string; body?: unknown; params?: Params } = {}): Promise<T> {
  const method = opts.method || 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
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
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/login')) window.dispatchEvent(new Event('nf:unauthorized'));
    throw new ApiError(res.status, errorMessage(body, res.status), typeof body?.pos === 'number' ? body.pos : undefined);
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
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { method: 'GET', credentials: 'same-origin', headers: { Accept: '*/*' } });
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Check that it is running.');
  }
  if (!res.ok) {
    const text = await res.text();
    let body: any = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    if (res.status === 401) window.dispatchEvent(new Event('nf:unauthorized'));
    throw new ApiError(res.status, errorMessage(body, res.status));
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
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-CSRF-Token': csrfToken() },
      body: form,
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Check that it is running.');
  }
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event('nf:unauthorized'));
    throw new ApiError(res.status, errorMessage(body, res.status));
  }
  return body as T;
}
