package engine_test

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/registry"
)

// PR #73 (ревью codex): сборки compose (make up/up-dev, ansible argus_images:
// build) должны нести тот же поставляемый набор, что образ релиза. Монтирование
// /rules его не заменяет: там бывают пользовательские правила. Образ engine
// собирается из корня репозитория (engine/Dockerfile копирует rules/ и
// fixtures/events/), поэтому именованные контексты и buildx не нужны.
// Run from engine: go test . -run 'Test(Compose|Release|Dockerfile)EngineRegistry' -count=1

func TestComposeEngineRegistryContexts(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Build struct {
				Context    string `yaml:"context"`
				Dockerfile string `yaml:"dockerfile"`
			} `yaml:"build"`
		} `yaml:"services"`
	}
	readRegistryPackagingYAML(t, "docker-compose.yml", &compose)
	b := compose.Services["engine"].Build
	if b.Context != "." || b.Dockerfile != "engine/Dockerfile" {
		t.Fatalf("compose собирает engine не из корня репозитория: context=%q dockerfile=%q", b.Context, b.Dockerfile)
	}
}

// Оба шага релиза (сканируемый образ и публикуемый) — из корня для engine.
func TestReleaseEngineRegistryContexts(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string `yaml:"uses"`
				With struct {
					Context string `yaml:"context"`
					File    string `yaml:"file"`
				} `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	readRegistryPackagingYAML(t, ".github/workflows/release.yml", &workflow)
	builds := 0
	for _, step := range workflow.Jobs["images"].Steps {
		if !strings.HasPrefix(step.Uses, "docker/build-push-action@") {
			continue
		}
		builds++
		if step.With.Context != "${{ matrix.service == 'engine' && '.' || format('./{0}', matrix.service) }}" ||
			step.With.File != "./${{ matrix.service }}/Dockerfile" {
			t.Errorf("шаг сборки релиза: context=%q file=%q — engine должен собираться из корня", step.With.Context, step.With.File)
		}
	}
	if builds == 0 {
		t.Fatal("no release image build found")
	}
}

// Dockerfile копирует набор, корневой .dockerignore его пропускает, и копии
// достаточно для реестра (правило SSH и словарь, который есть только в фикстурах).
func TestDockerfileEngineRegistryCopy(t *testing.T) {
	df, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"COPY rules/ /usr/share/argus/shipped/rules/", "COPY fixtures/events/ /usr/share/argus/shipped/fixtures/"} {
		if !strings.Contains(string(df), want) {
			t.Errorf("engine/Dockerfile: нет %q", want)
		}
	}
	f, err := os.Open(filepath.Join("..", ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	for _, want := range []string{"!engine/", "!rules/", "!fixtures/events/"} {
		if !slices.Contains(lines, want) {
			t.Errorf(".dockerignore не пропускает %s", want)
		}
	}
	if err := registry.LoadDirs(filepath.Join("..", "rules"), filepath.Join("..", "fixtures", "events")); err != nil {
		t.Fatalf("копия набора не даёт реестра: %v", err)
	}
	if _, ok := registry.LookupRule("a41c-auth-031"); !ok {
		t.Error("в наборе нет поставляемого правила SSH")
	}
	if !registry.Source("edr.kaspersky") || !registry.Action("file.read") {
		t.Error("в наборе нет словаря из фикстур")
	}
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

// Корневой .dockerignore пропускает только engine/, rules/ и fixtures/events/ —
// он действует на любую сборку с context: . Сейчас из корня собирается только
// engine; новый такой сервис должен сначала поправить .dockerignore.
func TestOnlyEngineBuildsFromRoot(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Build yaml.Node `yaml:"build"`
		} `yaml:"services"`
	}
	readRegistryPackagingYAML(t, "docker-compose.yml", &compose)
	for name, svc := range compose.Services {
		var ctx string
		switch svc.Build.Kind {
		case yaml.ScalarNode:
			ctx = svc.Build.Value
		case yaml.MappingNode:
			var b struct {
				Context string `yaml:"context"`
			}
			if err := svc.Build.Decode(&b); err != nil {
				t.Fatal(err)
			}
			ctx = b.Context
		default:
			continue
		}
		if c := filepath.Clean(ctx); (c == "." || c == "./") && name != "engine" {
			t.Errorf("compose: %s собирается из корня — корневой .dockerignore пропустит только engine/, rules/, fixtures/events/", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "matrix.service == 'engine' && '.'") {
		t.Error("release.yml: корневой контекст должен быть только у engine")
	}
}
