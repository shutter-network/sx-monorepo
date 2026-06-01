<script setup lang="ts">
import { ref } from 'vue';
import { fetchAuditPayload, verifyTally } from '@/helpers/teVerify';
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
  | { kind: 'ok'; tallies: bigint[]; matches: boolean | null }
  | { kind: 'err'; message: string };

const status = ref<Status>({ kind: 'idle' });

async function run() {
  status.value = { kind: 'fetching' };
  try {
    const payload = await fetchAuditPayload(
      props.apiBaseUrl,
      props.proposal.proposal_id as string
    );
    status.value = { kind: 'verifying' };
    const result = await verifyTally(
      props.proposal.proposal_id as string,
      payload,
      props.proposal.scores
    );
    status.value = {
      kind: 'ok',
      tallies: result.tallies,
      matches: result.matchesPublished
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
      Every ballot was encrypted under a threshold key and discarded after
      tally. The keypers' decryption shares and zero-knowledge proofs are
      public — anyone can recompute the totals from them and confirm the
      published scores were not forged.
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <button
        type="button"
        class="border rounded-lg px-3 py-1.5 hover:bg-skin-border"
        :disabled="status.kind === 'fetching' || status.kind === 'verifying'"
        @click="run"
      >
        <span v-if="status.kind === 'fetching'">Fetching shares...</span>
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
