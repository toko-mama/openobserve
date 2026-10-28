<template>
  <section
    class="flex h-full flex-col gap-3 overflow-auto p-4"
    data-test="incident-trace-occurrences"
  >
    <div class="flex items-center gap-3">
      <span>{{ t("alerts.incidents.traceOccurrenceTotal", { count: total }) }}</span>
      <OButton variant="outline" size="sm" :disabled="loading" @click="load">{{
        t("common.refresh")
      }}</OButton>
    </div>
    <p v-if="historyIncomplete" class="text-text-secondary text-sm">
      {{ t("alerts.incidents.traceOccurrenceHistoryIncomplete") }}
    </p>
    <p v-if="failed" role="alert">
      {{ t("alerts.incidents.traceOccurrencesFailed") }}
      <OButton variant="outline" size="sm" data-test="occurrences-retry" @click="load">{{
        t("common.retry")
      }}</OButton>
    </p>
    <OSpinner v-else-if="loading" size="lg" />
    <template v-else>
      <p v-if="!rows.length">{{ t("alerts.incidents.noTraceOccurrences") }}</p>
      <table v-else class="w-full text-left text-sm">
        <thead>
          <tr>
            <th class="p-2">{{ t("alerts.incidents.occurrenceTime") }}</th>
            <th class="p-2">{{ t("alerts.incidents.occurrenceTrace") }}</th>
            <th class="p-2">{{ t("alerts.incidents.occurrenceSpan") }}</th>
            <th class="p-2">{{ t("alerts.incidents.occurrenceStream") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in rows"
            :key="`${row.trace_id}:${row.span_id}`"
            data-test="occurrence-row"
          >
            <td class="p-2">{{ timestamp(row.timestamp) }}</td>
            <td class="p-2">
              <RouterLink :to="traceRoute(row)" class="text-text-link underline">{{
                row.trace_id
              }}</RouterLink>
            </td>
            <td class="p-2 font-mono">{{ row.span_id }}</td>
            <td class="p-2">{{ row.stream_name }}</td>
          </tr>
        </tbody>
      </table>
      <div class="flex items-center gap-3">
        <OButton variant="outline" size="sm" :disabled="offset === 0" @click="page(-1)">{{
          t("common.previous")
        }}</OButton>
        <span>{{ Math.floor(offset / pageSize) + 1 }}</span>
        <OButton
          variant="outline"
          size="sm"
          data-test="occurrences-next"
          :disabled="offset + pageSize >= total"
          @click="page(1)"
          >{{ t("common.next") }}</OButton
        >
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { ref, watch, onBeforeUnmount } from "vue";
import { RouterLink } from "vue-router";
import OButton from "@/lib/core/Button/OButton.vue";
import OSpinner from "@/lib/feedback/Spinner/OSpinner.vue";
import incidents, { type IncidentTraceOccurrence } from "@/services/incidents";
import { useI18nTyped } from "@/types/i18n";

const props = defineProps<{ orgIdentifier: string; incidentId: string }>();
const { t } = useI18nTyped();
const pageSize = 50;
const offset = ref(0);
const rows = ref<IncidentTraceOccurrence[]>([]);
const total = ref(0);
const historyIncomplete = ref(false);
const loading = ref(false);
const failed = ref(false);
let request = 0;
async function load() {
  const current = ++request;
  loading.value = true;
  failed.value = false;
  try {
    const { data } = await incidents.getTraceOccurrences(
      props.orgIdentifier,
      props.incidentId,
      pageSize,
      offset.value,
    );
    if (current !== request) return;
    rows.value = data.occurrences;
    total.value = data.total;
    historyIncomplete.value = data.history_incomplete;
  } catch {
    if (current === request) failed.value = true;
  } finally {
    if (current === request) loading.value = false;
  }
}
async function page(direction: number) {
  offset.value = Math.max(0, offset.value + direction * pageSize);
  await load();
}
const timestamp = (value: number) => {
  const date = new Date(value / 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : t("common.unknown");
};
const traceRoute = (row: IncidentTraceOccurrence) => ({
  name: "traceDetails",
  query: {
    org_identifier: props.orgIdentifier,
    stream: row.stream_name,
    trace_id: row.trace_id,
    from: String(row.timestamp - 300_000_000),
    to: String(row.timestamp + 300_000_000),
  },
});
watch(
  () => [props.orgIdentifier, props.incidentId],
  () => {
    offset.value = 0;
    rows.value = [];
    total.value = 0;
    historyIncomplete.value = false;
    void load();
  },
  { immediate: true },
);
onBeforeUnmount(() => {
  request++;
});
</script>
