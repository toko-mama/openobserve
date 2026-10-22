interface IncidentConfig {
  incidents_enabled?: boolean;
  incidents_ai_enabled?: boolean;
  incidents_topology_enabled?: boolean;
  oncall_enabled?: boolean;
}

export function incidentCapabilities(config: IncidentConfig, enterprise: boolean) {
  return {
    enabled: config.incidents_enabled === true,
    ai: enterprise && config.incidents_ai_enabled !== false,
    topology: enterprise && config.incidents_topology_enabled !== false,
    oncall: enterprise && config.oncall_enabled !== false,
  };
}
