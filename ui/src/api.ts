// The dashboard's only way to the Hub. Every change carries the session's
// CSRF token; a lost session sends the browser back through sign-in.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = '';

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function signIn() {
  const back = window.location.pathname + window.location.search;
  window.location.assign('/auth/login?return=' + encodeURIComponent(back));
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'NETWORK', 'The Hub could not be reached. Check your connection and try again.');
  }

  if (response.status === 401) {
    signIn();
    throw new ApiError(401, 'UNAUTHENTICATED', 'Signing you in again…');
  }
  if (response.status === 204) return undefined as T;

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const err = data?.error;
    throw new ApiError(response.status, err?.code ?? 'ERROR', err?.message ?? `Request failed (${response.status})`);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  del: <T = void>(path: string) => request<T>('DELETE', path),
};

export async function signOut() {
  const { redirect } = await request<{ redirect: string }>('POST', '/auth/logout');
  window.location.assign(redirect);
}
