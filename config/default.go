package config

const defaultCount = 4
const defaultMaxEntries = 500

func defaultParsedConfig() ParsedConfig {
	rulesDefault := RulesDefault{
		BanDuration: []string{"10m", "1h", "6h"},
		RegistryTTL: "24h",
		Actions:     []string{},
		Sockets:     []string{},
		Count:       defaultCount,
		MaxEntries:  defaultMaxEntries,
	}

	return ParsedConfig{
		Rules: map[string]Rule{
			"default": {},
		},
		LogLevel:      "info",
		AllowList:     "",
		ListenTCP:     "",
		ListenUnix:    "/var/run/secban/agent.sock",
		Profiler:      "localhost:6060",
		AllowLocal:    false,
		AllowLoopback: true,
		BanMethod:     "dummy",
		Database:      "/var/lib/secban/agent.sqlite",
		RulesDefault:  rulesDefault,
	}
}
