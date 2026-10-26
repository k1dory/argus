package identity

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// SyncFile — identities.yml в хранилище: все персоны и алиасы файла
// записываются заново с source = yaml; алиасы с source = yaml, которых в
// файле больше нет (сравнение по виду, значению, valid_from и персоне),
// помечаются deleted = 1. Персоны из файла не удаляются: у них могут быть
// алиасы из событий и API. Алиасы файла — точка истины для своих записей:
// отзыв событием закрывает их до следующей перезаписи файла. Политики
// алиасов (policies) вступают в силу после успешной записи файла; без
// IDENTITIES_FILE политик нет.
func (o *Observer) SyncFile(ctx context.Context, set Set) error {
	if o == nil || o.store == nil {
		return nil
	}
	err := o.syncFile(ctx, set)
	if err != nil {
		o.syncErr.Add(1)
		return err
	}
	o.syncOK.Add(1)
	return nil
}

func (o *Observer) syncFile(ctx context.Context, set Set) error {
	existing, err := o.store.AliasesBySource(ctx, SourceYAML)
	if err != nil {
		return fmt.Errorf("чтение алиасов yaml: %w", err)
	}
	if len(set.Persons) > 0 {
		if err := o.store.UpsertIdentities(ctx, set.Persons); err != nil {
			return fmt.Errorf("запись персон: %w", err)
		}
	}
	keep := map[string]bool{}
	for i := range set.Aliases {
		set.Aliases[i].Source = SourceYAML
		keep[set.Aliases[i].Key()] = true
	}
	if len(set.Aliases) > 0 {
		if err := o.store.UpsertAliases(ctx, set.Aliases); err != nil {
			return fmt.Errorf("запись алиасов: %w", err)
		}
	}
	var gone []Alias
	for _, a := range existing {
		if !keep[a.Key()] {
			gone = append(gone, a)
		}
	}
	if len(gone) > 0 {
		if err := o.store.DeleteAliases(ctx, gone); err != nil {
			return fmt.Errorf("пометка удалённых алиасов: %w", err)
		}
	}
	o.knownMu.Lock()
	for _, p := range set.Persons {
		o.known[p.ID] = true
	}
	o.knownMu.Unlock()
	o.SetPolicies(set.Policies)
	slog.Info("identity: файл применён", "persons", len(set.Persons), "aliases", len(set.Aliases), "deleted", len(gone), "policies", len(set.Policies))
	return nil
}

// Signature — отпечаток файла (размер и mtime) для перечитывания по
// изменению, как у каталога правил; "" — файла нет или он недоступен.
func Signature(path string) string {
	if path == "" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d|%d", st.Size(), st.ModTime().UnixNano())
}
