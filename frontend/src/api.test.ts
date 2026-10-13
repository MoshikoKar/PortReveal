import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, del, downloadBlob, errorMessage, get, newRequestId, patch, post, postForm, put } from './api';

type Call = { url: string; init: RequestInit };
let calls: Call[];
let events: string[];

function respond(status: number, body?: unknown, headers: Record<string, string> = {}) {
  const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(status === 204 ? null : text, { status, headers });
  }));
}

/** The ApiError a call rejects with (fails the test if it resolves). */
const failure = (p: Promise<unknown>): Promise<ApiError> =>
  p.then(() => { throw new Error('expected the request to fail'); }, (e: ApiError) => e);

const header = (c: Call, name: string) => (c.init.headers as Record<string, string>)[name];

beforeEach(() => {
  calls = [];
  events = [];
  vi.stubGlobal('document', { cookie: 'theme=dark; nf_csrf=tok%2Fen; other=1' });
  const target = new EventTarget();
  target.addEventListener('nf:unauthorized', () => events.push('nf:unauthorized'));
  vi.stubGlobal('window', target);
});

describe('CSRF header', () => {
  it('is sent with every state-changing method, decoded from the nf_csrf cookie', async () => {
    respond(200, {});
    await post('/networks', { name: 'x' });
    await put('/settings/scan', {});
    await patch('/users/1', {});
    await del('/networks/1');
    expect(calls.map((c) => c.init.method)).toEqual(['POST', 'PUT', 'PATCH', 'DELETE']);
    for (const c of calls) expect(header(c, 'X-CSRF-Token')).toBe('tok/en');
  });

  it('is not sent on GET', async () => {
    respond(200, []);
    await get('/networks');
    expect(header(calls[0], 'X-CSRF-Token')).toBeUndefined();
  });

  it('is empty when there is no csrf cookie (the backend then answers 403)', async () => {
    vi.stubGlobal('document', { cookie: '' });
    respond(200, {});
    await post('/networks', {});
    expect(header(calls[0], 'X-CSRF-Token')).toBe('');
  });

  it('is sent on multipart uploads', async () => {
    respond(200, { ok: true });
    await postForm('/data/import', new FormData());
    expect(header(calls[0], 'X-CSRF-Token')).toBe('tok/en');
    expect(header(calls[0], 'Content-Type')).toBeUndefined(); // the browser sets the multipart boundary
  });
});

describe('requests', () => {
  it('build /api URLs with query params and skip empty values', async () => {
    respond(200, []);
    await get('/devices', { q: 'web', page: 2, status: '', network_id: null, mine: undefined, all: false });
    expect(calls[0].url).toBe('/api/devices?q=web&page=2&all=false');
  });

  it('send JSON bodies and a request id', async () => {
    respond(201, { id: 1 });
    expect(await post('/networks', { name: 'Lab' })).toEqual({ id: 1 });
    expect(calls[0].init.body).toBe('{"name":"Lab"}');
    expect(header(calls[0], 'Content-Type')).toBe('application/json');
    expect(header(calls[0], 'X-Request-Id')).toMatch(/^[0-9a-f]{32}$/);
  });

  it('use a new request id per call', async () => {
    respond(200, {});
    await get('/a');
    await get('/b');
    expect(header(calls[0], 'X-Request-Id')).not.toBe(header(calls[1], 'X-Request-Id'));
  });

  it('return null for 204 No Content', async () => {
    respond(204);
    expect(await del('/networks/1')).toBeNull();
  });
});

describe('errors', () => {
  it('map a string detail and keep the status', async () => {
    respond(409, { detail: 'A user with this name already exists' });
    const err = await failure(post('/users', {}));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.message).toBe('A user with this name already exists');
  });

  it('carry the search syntax error position', async () => {
    respond(400, { detail: 'unknown field', pos: 4 });
    const err = await failure(get('/search', { q: 'nosuch:1' }));
    expect(err.pos).toBe(4);
  });

  it('add the server request id as a reference on 5xx only', async () => {
    respond(500, { detail: 'Internal Server Error' }, { 'X-Request-Id': 'srv-123' });
    const err = await failure(get('/dashboard'));
    expect(err.requestId).toBe('srv-123');
    expect(err.message).toBe('Internal Server Error (reference srv-123)');

    respond(422, { detail: 'bad' }, { 'X-Request-Id': 'srv-456' });
    const client = await failure(get('/dashboard'));
    expect(client.requestId).toBe('srv-456');
    expect(client.message).toBe('bad');
  });

  it('fall back to the sent request id when the response has none', async () => {
    respond(503, '<html>proxy error</html>');
    const err = await failure(get('/dashboard'));
    expect(err.requestId).toBe(header(calls[0], 'X-Request-Id'));
    expect(err.message).toBe(`Backend unavailable. Is the backend running? (reference ${err.requestId})`);
  });

  it('report an unreachable backend as status 0', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    const err = await failure(get('/dashboard'));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
  });

  it('signal 401s to the app, except for the login call itself', async () => {
    respond(401, { detail: 'Not authenticated' });
    await get('/dashboard').catch(() => undefined);
    expect(events).toEqual(['nf:unauthorized']);
    await api('/auth/login', { method: 'POST', body: {} }).catch(() => undefined);
    expect(events).toEqual(['nf:unauthorized']);
  });

  it('signal 401s from downloads', async () => {
    respond(401, { detail: 'Not authenticated' });
    await expect(downloadBlob('/data/export', 'x.zip')).rejects.toBeInstanceOf(ApiError);
    expect(events).toEqual(['nf:unauthorized']);
  });
});

describe('errorMessage', () => {
  it('joins FastAPI validation errors with their field path', () => {
    const body = {
      detail: [
        { loc: ['body', 'cidr'], msg: 'Value error, not a network' },
        { loc: ['query', 'page_size'], msg: 'Input should be less than or equal to 500' },
        { msg: 'whole body invalid' },
      ],
    };
    expect(errorMessage(body, 422)).toBe(
      'cidr: not a network; query.page_size: Input should be less than or equal to 500; whole body invalid',
    );
  });

  it('explains gateway errors and falls back to the status', () => {
    for (const s of [502, 503, 504]) expect(errorMessage(null, s)).toBe('Backend unavailable. Is the backend running?');
    expect(errorMessage({}, 418)).toBe('Request failed (418)');
  });
});

describe('newRequestId', () => {
  it('works without crypto.randomUUID (plain-HTTP LAN installs are not a secure context)', () => {
    vi.stubGlobal('isSecureContext', false);
    expect(newRequestId()).toMatch(/^[0-9a-f]{32}$/);
  });
});
