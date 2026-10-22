import { describe, expect, it } from "vitest";
import { incidentCapabilities } from "./incidentCapabilities";

describe("incidentCapabilities", () => {
  it("enables OSS incidents without enterprise dependencies", () => {
    expect(incidentCapabilities({ incidents_enabled: true }, false)).toEqual({
      enabled: true,
      ai: false,
      topology: false,
      oncall: false,
    });
  });
  it("hides navigation while disabled or config is loading", () => {
    expect(incidentCapabilities({ incidents_enabled: false }, false).enabled).toBe(false);
    expect(incidentCapabilities({}, false).enabled).toBe(false);
  });
  it("preserves enterprise features unless explicitly disabled", () => {
    expect(incidentCapabilities({ incidents_enabled: true }, true)).toEqual({
      enabled: true,
      ai: true,
      topology: true,
      oncall: true,
    });
  });
});
