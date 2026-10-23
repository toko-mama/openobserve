import { mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { describe, expect, it } from "vitest";
import IncidentErrorSummary from "./IncidentErrorSummary.vue";
import i18n from "@/locales";

const error = {
  service: "checkout's service",
  exception_type: "TypeError",
  message: "Cannot read cart",
  stacktrace: "TypeError: Cannot read cart\n  at checkout",
  operation: "POST /checkout",
  occurrence_count: 12,
  first_seen: 1700000000000000,
  last_seen: 1700000600000000,
  latest_trace: {
    trace_id: "abc123",
    span_id: "span1",
    stream_name: "app traces",
    timestamp: 1700000300000000,
  },
};
async function render(errorTracking?: typeof error) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: { template: "<div/>" } },
      { path: "/traces", name: "traces", component: { template: "<div/>" } },
      { path: "/trace", name: "traceDetails", component: { template: "<div/>" } },
    ],
  });
  await router.push("/");
  await router.isReady();
  return {
    router,
    wrapper: mount(IncidentErrorSummary, {
      props: { errorTracking, orgIdentifier: "my-org" },
      global: { plugins: [router, i18n] },
    }),
  };
}
describe("IncidentErrorSummary", () => {
  it("omits the summary for alert incidents", async () => {
    const { wrapper } = await render();
    expect(wrapper.find('[data-test="incident-error-summary"]').exists()).toBe(false);
  });
  it("renders grouped occurrences and exception evidence", async () => {
    const { wrapper } = await render(error);
    expect(wrapper.text()).toContain("Occurrences: 12");
    expect(wrapper.text()).toContain("TypeError");
    expect(wrapper.text()).toContain("Cannot read cart");
    expect(wrapper.find("pre").text()).toBe(error.stacktrace);
    expect(wrapper.text()).toContain("2023-11-14T22:13:20.000Z");
  });
  it("links the latest trace with microsecond bounds and encodes the service filter", async () => {
    const { wrapper, router } = await render(error);
    const latest = router.resolve(
      wrapper.find('[data-test="incident-error-trace"]').attributes("href"),
    );
    expect(latest.query).toMatchObject({
      trace_id: "abc123",
      stream: "app traces",
      org_identifier: "my-org",
      from: "1699999700000000",
      to: "1700000900000000",
    });
    const service = router.resolve(
      wrapper.find('[data-test="incident-error-service"]').attributes("href"),
    );
    expect(service.query.filter).toBe("service_name = 'checkout''s service'");
    expect(service.query.from).toBe("1699999700000000");
  });
});
