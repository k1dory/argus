package analyst

import "gopkg.in/yaml.v3"

func yamlUnmarshal(s string, v any) error { return yaml.Unmarshal([]byte(s), v) }
