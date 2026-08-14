/**
 * The hub client, and the status contract this service must preserve.
 *
 * The protocol's data-layer client maps HTTP status onto typed errors, and its
 * callers branch on those types — a coordinator treats an authorisation failure,
 * an immutability conflict and an out-of-window write completely differently. So
 * status codes here are not cosmetic: collapsing them all to 500 would make the
 * coordinator retry things it should abandon, and abandon things it should retry.
 *
 *   404 → unknown election            (the client raises a lookup error)
 *   403 → not authorised to write
 *   409 → append-only violation / already finalised
 *   422 → write outside the permitted window or ordering
 *   400 → malformed request
 *
 * This service holds no keys and owns no storage. Everything it serves comes from
 * the hub, which is the sole store of record.
 */

import fetch from 'node-fetch';

export class HubError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
  }
}

const TIMEOUT_MS = Number(process.env.HUB_TIMEOUT_MS || 10000);

function hubBase(): string {
  const url = process.env.HUB_URL;
  if (!url?.trim()) {
    throw new HubError('HUB_URL is not configured', 500);
  }
  return url.trim().replace(/\/+$/, '');
}

/**
 * GET from the hub, surfacing its status as-is.
 *
 * Statuses pass straight through rather than being remapped. The hub already
 * answers 404 for an unknown proposal and 503 when private voting is not
 * configured, and both mean the same thing to the caller as they do here.
 */
export async function hubGet<T>(path: string): Promise<T> {
  const url = `${hubBase()}${path}`;
  let res;
  try {
    res = await fetch(url, {
      timeout: TIMEOUT_MS,
      headers: { accept: 'application/json' }
    });
  } catch (err: any) {
    // The hub being unreachable is not the caller's fault, and it is retryable —
    // 502 says exactly that, where a 500 would suggest a bug in this service.
    throw new HubError(`hub unreachable: ${err?.message || err}`, 502);
  }

  let body: any = null;
  try {
    body = await res.json();
  } catch {
    // A non-JSON body from an error status is still a usable signal.
    if (res.ok) throw new HubError('hub returned a non-JSON body', 502);
  }

  if (!res.ok) {
    throw new HubError(
      body?.error || body?.message || `hub responded ${res.status}`,
      res.status
    );
  }
  return body as T;
}

/**
 * POST to the hub, surfacing its status as-is.
 *
 * Status fidelity matters more on writes than on reads. The protocol's client maps
 * 403 to an authorisation failure, 409 to an append-only violation and 422 to an
 * out-of-window write, and the coordinator's retry policy differs for each: a 409
 * from a quorum race is benign and logged, while a 403 means a misconfigured
 * committee and should stop the ceremony. Collapsing them would make it retry what
 * it should abandon.
 *
 * A 204 carries no body, which is what the port's write methods return.
 */
export async function hubPost<T>(
  path: string,
  payload: unknown
): Promise<T | null> {
  const url = `${hubBase()}${path}`;
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      timeout: TIMEOUT_MS,
      headers: {
        'content-type': 'application/json',
        accept: 'application/json'
      },
      body: JSON.stringify(payload)
    });
  } catch (err: any) {
    throw new HubError(`hub unreachable: ${err?.message || err}`, 502);
  }

  if (res.status === 204) return null;

  let body: any = null;
  try {
    body = await res.json();
  } catch {
    if (res.ok) return null;
  }

  if (!res.ok) {
    throw new HubError(
      body?.error || body?.message || `hub responded ${res.status}`,
      res.status
    );
  }
  return body as T;
}
