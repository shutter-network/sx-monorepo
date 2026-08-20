/**
 * Reading and clearing a stalled tally.
 *
 * A stalled tally is one the keyper committee could not complete: the coordinator
 * exhausted its attempts and persisted a flag saying so.
 */

import { requestDigest } from './gegRequest';

/** What the hub reports for a geg election. Only the fields the stall UI needs. */
export type GegElectionState = {
  tallyStalled: boolean;
};

function endpoint(
  apiBaseUrl: string,
  proposalId: string,
  route: string
): string {
  return `${apiBaseUrl.replace(/\/$/, '')}/proposal/${encodeURIComponent(proposalId)}/${route}`;
}

export async function fetchGegElection(
  apiBaseUrl: string,
  proposalId: string
): Promise<GegElectionState> {
  const r = await fetch(endpoint(apiBaseUrl, proposalId, 'te_geg_election'), {
    credentials: 'omit'
  });
  if (!r.ok) throw new Error(`hub ${r.status}: ${await r.text()}`);
  const body = await r.json();
  return { tallyStalled: Boolean(body?.tallyStalled) };
}

/**
 * Ask the hub to clear the stall, authorised by the admin's wallet signature over
 * `requestDigest('tally_resume', proposalId)`.
 *
 * The digest is signed as raw bytes: `signMessage` on a `Uint8Array` is EIP-191 over
 * those bytes, which is what the hub's `verifyMessage` reverses. Passing the hex
 * *string* would sign 66 ASCII characters instead and recover a different address —
 * refused as `not_the_admin`, which reads like the wallet is wrong rather than the
 * encoding.
 */
export async function submitTallyResume(
  apiBaseUrl: string,
  proposalId: string,
  signRaw: (digest: Uint8Array) => Promise<string>
): Promise<void> {
  const adminSig = await signRaw(requestDigest('tally_resume', proposalId));
  const r = await fetch(endpoint(apiBaseUrl, proposalId, 'te_tally_stalled'), {
    method: 'POST',
    credentials: 'omit',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ stalled: false, adminSig })
  });
  if (r.status === 403) {
    throw new Error(
      "The hub refused this signature. Only an admin of this proposal's space can retry a tally."
    );
  }
  if (!r.ok) throw new Error(`hub ${r.status}: ${await r.text()}`);
}
