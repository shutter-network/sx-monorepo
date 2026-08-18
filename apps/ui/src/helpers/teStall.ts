/**
 * Reading and clearing a stalled tally.
 *
 * A stalled tally is one the keyper committee could not complete: the coordinator
 * exhausted its attempts and persisted a flag saying so. The flag is deliberately
 * *persisted* rather than held in the coordinator's memory, because the retry budget
 * is in memory — if a restart alone resumed the election, a genuinely stuck tally
 * would retry and stall in a loop instead of waiting for a person.
 *
 * That is why clearing it is a human action, and why the clear is signed by a
 * different identity than the one that set it. The coordinator marks the stall with
 * its own key; only `TE_ADMIN_ADDRESS` can clear it, and the operation name is inside
 * the signed message, so the coordinator's stall signature is not a resume signature.
 *
 * The flag is not on the GraphQL proposal — it is private-voting state that only
 * `shutter-elgamal` proposals ever carry — so it is read over the hub's REST surface,
 * the same way the audit panel reads shares.
 */

import { requestDigest } from './gegRequest';

/** What the hub reports for a geg election. Only the fields the stall UI needs. */
export type GegElectionState = {
  tallyStalled: boolean;
  /** Lowercased address permitted to clear a stall (`config.adminKey`). */
  adminAddress: string | null;
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
  return {
    tallyStalled: Boolean(body?.tallyStalled),
    adminAddress: body?.config?.adminKey ?? null
  };
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
      'The hub refused this signature. Only the configured admin wallet can retry a tally.'
    );
  }
  if (!r.ok) throw new Error(`hub ${r.status}: ${await r.text()}`);
}
