<template>
  <section
    v-if="errorTracking"
    class="border-card-glass-border bg-card-glass-bg rounded-default mb-3 border p-3"
    data-test="incident-error-summary"
  >
    <div class="flex flex-wrap items-center gap-3">
      <h2 class="text-text-heading text-sm font-semibold">
        {{ t("alerts.incidents.errorIssue") }}
      </h2>
      <span>{{
        t("alerts.incidents.errorOccurrences", { count: errorTracking.occurrence_count })
      }}</span>
      <RouterLink
        v-if="errorTracking.service"
        :to="serviceRoute"
        class="text-text-link underline"
        data-test="incident-error-service"
        >{{ errorTracking.service }}</RouterLink
      >
      <span>{{ errorTracking.operation }}</span>
      <RouterLink
        v-if="errorTracking.latest_trace.trace_id"
        :to="traceRoute"
        class="text-text-link underline"
        data-test="incident-error-trace"
        >{{ t("alerts.incidents.viewLatestErrorTrace") }}</RouterLink
      >
    </div>
    <div class="text-text-secondary mt-2 flex flex-wrap gap-3 text-xs">
      <span>{{
        t("alerts.incidents.errorFirstSeen", { time: timestamp(errorTracking.first_seen) })
      }}</span>
      <span>{{
        t("alerts.incidents.errorLastSeen", { time: timestamp(errorTracking.last_seen) })
      }}</span>
    </div>
    <p class="mt-2 break-words">
      <strong>{{ errorTracking.exception_type }}</strong> {{ errorTracking.message }}
    </p>
    <pre
      v-if="errorTracking.stacktrace"
      class="bg-surface-panel mt-2 max-h-48 overflow-auto rounded p-2 text-xs whitespace-pre-wrap"
      >{{ errorTracking.stacktrace }}</pre>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import type { IncidentErrorTracking } from "@/services/incidents";
import { useI18nTyped } from "@/types/i18n";
import { buildViewTracesFilter } from "@/plugins/traces/viewTracesHandoff";

const props = defineProps<{ errorTracking?: IncidentErrorTracking; orgIdentifier: string }>();
const { t } = useI18nTyped();
const timestamp = (value: number) => {
  const date = new Date(value / 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : t("common.unknown");
};
const bounds = computed(() => {
  const error = props.errorTracking;
  if (!error) return {};
  return {
    stream: error.latest_trace.stream_name,
    org_identifier: props.orgIdentifier,
    from: String(Math.min(error.first_seen, error.latest_trace.timestamp) - 300_000_000),
    to: String(Math.max(error.last_seen, error.latest_trace.timestamp) + 300_000_000),
  };
});
const traceRoute = computed(() => ({
  name: "traceDetails",
  query: { ...bounds.value, trace_id: props.errorTracking?.latest_trace.trace_id },
}));
const serviceRoute = computed(() => ({
  name: "traces",
  query: {
    ...bounds.value,
    tab: "traces",
    filter: buildViewTracesFilter({ serviceName: props.errorTracking?.service }),
  },
}));
</script>
