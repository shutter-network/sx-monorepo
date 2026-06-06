<script setup lang="ts">
import { ref } from 'vue';
import {
  fetchAuditPayload,
  fetchBallotsPayload,
  verifyBallots,
  verifyTally,
  type BallotAuditResult
} from '@/helpers/teVerify';
import type { Proposal } from '@/types';

const props = defineProps<{
  proposal: Proposal;
  /** Hub root, ending in `/api` (e.g. `https://hub.snapshot.org/api`). */
  apiBaseUrl: string;
}>();

type Status =
  | { kind: 'idle' }
  | { kind: 'fetching' }
  | { kind: 'verifying' }
  | {
      kind: 'ok';
      tallies: bigint[];
      matches: boolean | null;
      ballots: BallotAuditResult;
    }
  | { kind: 'err'; message: string };

const status = ref<Status>({ kind: 'idle' });

async function run() {
  status.value = { kind: 'fetching' };
  try {
    const proposalId = props.proposal.proposal_id as string;
    const [payload, ballotsPayload] = await Promise.all([
      fetchAuditPayload(props.apiBaseUrl, proposalId),
      fetchBallotsPayload(props.apiBaseUrl, proposalId)
    ]);
    status.value = { kind: 'verifying' };
    // Step 1: independently verify every encrypted ballot and re-derive
    // the vp-weighted aggregate the keypers decrypted.
    const ballots = await verifyBallots(
      proposalId,
      ballotsPayload,
      payload.aggregate
    );
    // Step 2: recover the tally from the public decryption shares.
    const result = await verifyTally(
      proposalId,
      payload,
      props.proposal.scores
    );
    status.value = {
      kind: 'ok',
      tallies: result.tallies,
      matches: result.matchesPublished,
      ballots
    };
  } catch (err: any) {
    status.value = { kind: 'err', message: err?.message || String(err) };
  }
}
</script>

<template>
  <div class="border rounded-lg px-3 py-2.5 mt-2.5 space-y-2">
    <div class="flex items-center gap-2 text-skin-link font-semibold">
      <IH-shield-check class="size-[18px]" />
      Permanent private tally
    </div>
    <div class="text-skin-text text-sm">
      Every ballot was encrypted under a threshold key and never individually
      decrypted. Anyone can independently (1) check each encrypted ballot's
      zero-knowledge validity proof, (2) recompute the voting-power-weighted
      aggregate and confirm it matches what the keypers decrypted, and (3)
      recompute the totals from the keypers' public decryption shares — proving
      the published scores were neither forged nor stuffed with invalid votes.
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <button
        type="button"
        class="border rounded-lg px-3 py-1.5 hover:bg-skin-border"
        :disabled="status.kind === 'fetching' || status.kind === 'verifying'"
        @click="run"
      >
        <span v-if="status.kind === 'fetching'">Fetching ballots...</span>
        <span v-else-if="status.kind === 'verifying'">Verifying...</span>
        <span v-else>Verify tally</span>
      </button>
      <span
        v-if="status.kind === 'ok' && status.matches === true"
        class="text-skin-success flex items-center gap-1"
      >
        <IH-check-circle class="size-[16px]" />
        Tally matches published scores.
      </span>
      <span
        v-else-if="status.kind === 'ok' && status.matches === false"
        class="text-skin-danger flex items-center gap-1"
      >
        <IH-x-circle class="size-[16px] shrink-0" />
        Mismatch — the recomputed tally differs from the published scores.
      </span>
      <span
        v-else-if="status.kind === 'ok'"
        class="text-skin-link flex items-center gap-1"
      >
        <IH-check-circle class="size-[16px]" />
        Shares verified; recomputed totals available below.
      </span>
      <span
        v-else-if="status.kind === 'err'"
        class="text-skin-danger break-all"
      >
        {{ status.message }}
      </span>
    </div>
    <div
      v-if="status.kind === 'ok'"
      class="text-sm flex items-center gap-1"
      :class="
        status.ballots.aggregateMatches &&
        status.ballots.failures.length === 0
          ? 'text-skin-success'
          : 'text-skin-danger'
      "
    >
      <IH-check-circle
        v-if="
          status.ballots.aggregateMatches &&
          status.ballots.failures.length === 0
        "
        class="size-[16px] shrink-0"
      />
      <IH-x-circle v-else class="size-[16px] shrink-0" />
      <span v-if="status.ballots.failures.length === 0">
        {{ status.ballots.verifiedCount }}/{{ status.ballots.total }} ballots
        passed their zero-knowledge proof and the recomputed aggregate
        {{ status.ballots.aggregateMatches ? 'matches' : 'does NOT match' }}
        the decrypted one.
      </span>
      <span v-else>
        {{ status.ballots.failures.length }} of
        {{ status.ballots.total }} ballots failed verification
        (e.g. {{ status.ballots.failures[0].reason }}).
      </span>
    </div>
    <ul
      v-if="status.kind === 'ok'"
      class="text-sm text-skin-text grid grid-cols-2 gap-x-4"
    >
      <li
        v-for="(tally, i) in status.tallies"
        :key="i"
        class="flex justify-between"
      >
        <span class="truncate">
          {{ proposal.choices?.[i] || `Choice ${i + 1}` }}
        </span>
        <span class="font-mono">{{ tally.toString() }}</span>
      </li>
    </ul>
  </div>
</template>
