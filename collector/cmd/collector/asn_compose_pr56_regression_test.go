package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// .env supplies Compose interpolation; it does not automatically become the
// environment of a container. Both documented ASN controls must reach the
// collector, otherwise openASN silently uses 10000 rows and a one-minute poll.
func TestPR56ComposeForwardsASNControls(t *testing.T) {
	data, err := os.ReadFile("../../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatal(err)
	}
	collector, ok := compose.Services["collector"]
	if !ok {
		t.Fatal("collector service missing")
	}
	for _, key := range []string{"ASN_DB_MIN_ROWS", "ASN_DB_RELOAD"} {
		t.Run(key, func(t *testing.T) {
			value, exists := collector.Environment[key]
			if !exists || !(strings.Contains(value, "${"+key+"}") ||
				strings.Contains(value, "${"+key+":-") || value == "$"+key) {
				t.Fatalf(".env %s never reaches collector: environment entry = %q, exists = %v", key, value, exists)
			}
		})
	}
}
