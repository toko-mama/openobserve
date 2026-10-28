import { mount, flushPromises } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { describe, expect, it, vi, beforeEach } from "vitest";
import i18n from "@/locales";
import incidents from "@/services/incidents";
import IncidentTraceOccurrences from "./IncidentTraceOccurrences.vue";

vi.mock("@/services/incidents", () => ({ default: { getTraceOccurrences: vi.fn() } }));
const reference = {
  trace_id: "trace-one",
  span_id: "span-one",
  stream_name: "otel",
  timestamp: 1700000000000000,
};
async function render() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: { template: "<div/>" } },
      { path: "/trace", name: "traceDetails", component: { template: "<div/>" } },
    ],
  });
  await router.push("/");
  const wrapper = mount(IncidentTraceOccurrences, {
    props: { orgIdentifier: "default", incidentId: "issue" },
    global: { plugins: [router, i18n] },
  });
  await flushPromises();
  return { wrapper, router };
}
describe("IncidentTraceOccurrences", () => {
  beforeEach(() => vi.mocked(incidents.getTraceOccurrences).mockReset());
  it("shows distinct spans and links each occurrence to its own trace bounds", async () => {
    vi.mocked(incidents.getTraceOccurrences).mockResolvedValue({
      data: {
        occurrences: [
          reference,
          { ...reference, span_id: "span-two", timestamp: reference.timestamp + 10 },
        ],
        total: 2,
        history_incomplete: false,
      },
    } as any);
    const { wrapper, router } = await render();
    expect(wrapper.findAll('[data-test="occurrence-row"]')).toHaveLength(2);
    expect(wrapper.text()).toContain("span-two");
    expect(router.resolve(wrapper.find("a").attributes("href")).query).toMatchObject({
      trace_id: "trace-one",
      stream: "otel",
      org_identifier: "default",
      from: "1699999700000000",
      to: "1700000300000000",
    });
  });
  it("fetches the next page and explains missing legacy history", async () => {
    vi.mocked(incidents.getTraceOccurrences)
      .mockResolvedValueOnce({
        data: { occurrences: [reference], total: 51, history_incomplete: true },
      } as any)
      .mockResolvedValueOnce({
        data: {
          occurrences: [{ ...reference, trace_id: "older-trace" }],
          total: 51,
          history_incomplete: true,
        },
      } as any);
    const { wrapper } = await render();
    expect(wrapper.text()).toContain("Older occurrence references were not retained");
    await wrapper.find('[data-test="occurrences-next"]').trigger("click");
    await flushPromises();
    expect(incidents.getTraceOccurrences).toHaveBeenLastCalledWith("default", "issue", 50, 50);
    expect(wrapper.text()).toContain("older-trace");
  });
  it("shows a retry after failure instead of claiming there are no occurrences", async () => {
    vi.mocked(incidents.getTraceOccurrences)
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce({
        data: { occurrences: [], total: 0, history_incomplete: false },
      } as any);
    const { wrapper } = await render();
    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    await wrapper.find('[data-test="occurrences-retry"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[role="alert"]').exists()).toBe(false);
  });
  it("ignores responses from a previously selected incident", async () => {
    let finishFirst!: (value: any) => void;
    vi.mocked(incidents.getTraceOccurrences).mockReturnValueOnce(
      new Promise((resolve) => {
        finishFirst = resolve;
      }),
    );
    const { wrapper } = await render();
    vi.mocked(incidents.getTraceOccurrences).mockResolvedValueOnce({
      data: {
        occurrences: [{ ...reference, trace_id: "new-issue-trace" }],
        total: 1,
        history_incomplete: false,
      },
    } as any);
    await wrapper.setProps({ incidentId: "new-issue" });
    await flushPromises();
    finishFirst({ data: { occurrences: [reference], total: 1, history_incomplete: false } });
    await flushPromises();
    expect(wrapper.text()).toContain("new-issue-trace");
    expect(wrapper.text()).not.toContain("trace-one");
  });
});
