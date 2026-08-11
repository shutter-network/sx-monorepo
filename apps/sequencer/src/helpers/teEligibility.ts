/**
 * Fetch the eligibility public key from the hub, for freezing onto a proposal.
 *
 * The hub holds the eligibility *private* key and signs one credential per
 * ballot, binding that ballot's voting-power weight. The keypers verify those
 * credentials against the public key frozen in the proposal's config — so if the
 * frozen key and the hub's actual key ever disagree, every credential fails to
 * verify, every ballot is excluded from the tally, and the result is all zeros
 * with nothing in the logs to explain it.
 *
 * The defence is to have exactly one source of truth. Rather than configuring the
 * public key separately here (two copies, free to drift), the sequencer asks the
 * hub for it at creation and freezes whatever it answers. The hub additionally
 * asserts the frozen key still matches its own on every read, which catches a key
 * rotated after the fact.
 *
 * Fetch failures reject the proposal. That is deliberate: a private proposal
 * created with no eligibility key is one whose tally can never complete, and
 * refusing it up front is strictly kinder than discovering that after voting.
 *
 * The key is a deployment constant, so it is cached for the process lifetime —
 * one request per sequencer, not one per proposal.
 */

import fetch from 'node-fetch';
import log from './log';

export class TeEligibilityError extends Error {}

const TIMEOUT_MS = 5000;

let cached: string | null = null;

function hubUrl(): string {
  const url = process.env.HUB_URL;
  if (!url?.trim()) {
    throw new TeEligibilityError(
      'HUB_URL is not configured; cannot fetch the eligibility key'
    );
  }
  return url.trim().replace(/\/+$/, '');
}

/** Test seam: drop the cached key so a test can vary the hub response. */
export function resetEligibilityKeyCache(): void {
  cached = null;
}

export async function getEligibilityKey(): Promise<string> {
  if (cached) return cached;

  const url = `${hubUrl()}/api/te_eligibility_key`;
  let body: any;
  try {
    const res = await fetch(url, {
      timeout: TIMEOUT_MS,
      headers: { accept: 'application/json' }
    });
    if (!res.ok) {
      throw new TeEligibilityError(`hub responded ${res.status}`);
    }
    body = await res.json();
  } catch (err: any) {
    throw new TeEligibilityError(
      `could not fetch the eligibility key from ${url}: ${err?.message || err}`
    );
  }

  const key = body?.eligibilityKey;
  if (typeof key !== 'string' || !/^0x[0-9a-fA-F]{96}$/.test(key)) {
    throw new TeEligibilityError(
      'hub returned a malformed eligibility key (expected 0x + 96 hex chars)'
    );
  }

  cached = key.toLowerCase();
  log.info(`[te] eligibility key ${cached.slice(0, 12)}… loaded from hub`);
  return cached;
}
