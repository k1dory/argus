package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/registry"
)

// PR #73: compose builds used by make up/up-dev must carry the same shipped
// registry as the release image. The /rules runtime mount cannot replace it:
// that mount may contain private operator rules.
// Run from engine: go test . -run 'Test(Compose|Release)EngineRegistry' -count=1
func TestComposeEngineRegistryContexts(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Build struct {
				AdditionalContexts yaml.Node `yaml:"additional_contexts"`
			} `yaml:"build"`
		} `yaml:"services"`
	}
	readRegistryPackagingYAML(t, "docker-compose.yml", &compose)
	node := compose.Services["engine"].Build.AdditionalContexts
	contexts := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		if err := node.Decode(&contexts); err != nil {
			t.Fatal(err)
		}
	case yaml.SequenceNode:
		var entries []string
		if err := node.Decode(&entries); err != nil {
			t.Fatal(err)
		}
		contexts = registryContextEntries(entries)
	}
	checkRegistryBuildContexts(t, contexts)
}

// Both the locally scanned image and the pushed image need the bundle.
func TestReleaseEngineRegistryContexts(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string `yaml:"uses"`
				With struct {
					BuildContexts string `yaml:"build-contexts"`
				} `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	readRegistryPackagingYAML(t, ".github/workflows/release.yml", &workflow)
	builds := 0
	for _, step := range workflow.Jobs["images"].Steps {
		if strings.HasPrefix(step.Uses, "docker/build-push-action@") {
			builds++
			checkRegistryBuildContexts(t, registryContextEntries(strings.Split(step.With.BuildContexts, "\n")))
		}
	}
	if builds == 0 {
		t.Fatal("no release image build found")
	}
}

func registryContextEntries(entries []string) map[string]string {
	out := map[string]string{}
	for _, entry := range entries {
		if name, path, ok := strings.Cut(strings.TrimSpace(entry), "="); ok {
			out[name] = path
		}
	}
	return out
}

func readRegistryPackagingYAML(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

func checkRegistryBuildContexts(t *testing.T, contexts map[string]string) {
	t.Helper()
	for _, name := range []string{"rules", "fixtures"} {
		if strings.TrimSpace(contexts[name]) == "" {
			t.Errorf("engine build omits named context %q: the Dockerfile's scratch fallback has no registry data", name)
		}
	}
	if contexts["rules"] == "" || contexts["fixtures"] == "" {
		return
	}
	if err := registry.LoadDirs(filepath.Join("..", contexts["rules"]), filepath.Join("..", contexts["fixtures"])); err != nil {
		t.Fatalf("configured image contexts do not contain a usable registry: %v", err)
	}
	if _, ok := registry.LookupRule("a41c-auth-031"); !ok {
		t.Error("configured rule context omits the shipped SSH rule")
	}
	if !registry.Source("edr.kaspersky") || !registry.Action("file.read") {
		t.Error("configured fixture context omits fixture-only vocabulary")
	}
}
