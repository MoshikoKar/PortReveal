import { describe, expect, it } from 'vitest';
import { httpTitleDisplay } from './util';

describe('httpTitleDisplay', () => {
  it.each([
    [403, '403 - Forbidden', 'Forbidden'],
    [403, '403: Forbidden', 'Forbidden'],
    [403, 'HTTP 403 Forbidden', 'Forbidden'],
    [403, 'HTTP/1.1 403 Forbidden', 'Forbidden'],
    [403, '403 Forbidden', 'Forbidden'],
    [406, '406 - Client browser does not accept the MIME type of the requested page.', 'Client browser does not accept the MIME type of the requested page.'],
    [404, '404 Not Found', 'Not Found'],
  ])('strips a leading %s from %j', (status, title, out) => {
    expect(httpTitleDisplay(status, title)).toBe(out);
  });

  it('returns null when only the status was there', () => {
    expect(httpTitleDisplay(403, '403')).toBeNull();
    expect(httpTitleDisplay(403, ' HTTP 403 - ')).toBeNull();
    expect(httpTitleDisplay(200, null)).toBeNull();
  });

  it('leaves titles without the same leading status alone', () => {
    expect(httpTitleDisplay(200, 'Router login')).toBe('Router login');
    expect(httpTitleDisplay(403, '404 Not Found')).toBe('404 Not Found');
    expect(httpTitleDisplay(403, '4030 items')).toBe('4030 items');
    expect(httpTitleDisplay(null, '403 Forbidden')).toBe('403 Forbidden');
  });
});
