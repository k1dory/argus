.PHONY: up up-dev down demo deploy verify-images build test policy-test rust-test go-test sample logs migrate rules-test replay collector-test engine-test mcp mcp-test triage-test lint check

APP_VERSION := $(shell cat VERSION)
COMPOSE_DEV := docker compose --env-file .env.dev -f docker-compose.yml -f docker-compose.dev.yml

up: ## Собрать и поднять стек (.env от ./scripts/argus init; профили — COMPOSE_PROFILES из .env: wazuh, mcp)
	APP_VERSION=$(APP_VERSION) docker compose up -d --build

up-dev: ## Стенд: дефолтные секреты из .env.dev, ARGUS_DEV=1 (docker-compose.dev.yml)
	APP_VERSION=$(APP_VERSION) $(COMPOSE_DEV) up -d --build

down:
	docker compose down

demo: sample replay ## Демо-данные: записанный трафик → инциденты; свежие алерты Wazuh (./sample) — при профиле wazuh

deploy: verify-images ## Прод: образы версии из реестра (ARGUS_IMAGE_PREFIX в .env), без сборки на хосте
	APP_VERSION=$(APP_VERSION) docker compose pull
	APP_VERSION=$(APP_VERSION) docker compose up -d --no-build

verify-images: ## Проверить подписи cosign образов версии (COSIGN_PUBKEY в .env; пусто — предупреждение)
	@set -e; . ./.env 2>/dev/null || true; \
	if [ -z "$$COSIGN_PUBKEY" ]; then echo "verify-images: COSIGN_PUBKEY не задан — подписи не проверяются"; exit 0; fi; \
	command -v cosign >/dev/null || { echo "verify-images: cosign не установлен, а COSIGN_PUBKEY задан"; exit 1; }; \
	for s in shipper policyd collector engine web mcp; do \
	  img="$${ARGUS_IMAGE_PREFIX:?ARGUS_IMAGE_PREFIX не задан}/$$s:$(APP_VERSION)"; \
	  cosign verify --key "$$COSIGN_PUBKEY" "$$img" >/dev/null || { echo "verify-images: подпись $$img не прошла"; exit 1; }; \
	  echo "verify-images: $$img ok"; \
	done

check: ## Валидность compose и скриптов: docker compose config, bash -n, shellcheck (если есть)
	$(COMPOSE_DEV) config --quiet
	$(COMPOSE_DEV) --profile wazuh --profile mcp config --quiet
	@for f in scripts/*.sh scripts/argus; do bash -n "$$f" || exit 1; done
	@if command -v shellcheck >/dev/null; then shellcheck -S warning scripts/*.sh scripts/argus; else echo "shellcheck не установлен — пропуск"; fi

lint: ## То же, что CI: gofmt/vet, eslint, cargo fmt/clippy
	@for m in collector engine policyd mcp triage; do (cd $$m && test -z "$$(gofmt -l .)" && go vet ./...) || exit 1; done
	cd web && npx eslint src
	cd shipper && cargo fmt --check && cargo clippy --all-targets -- -D warnings

migrate: ## Прогнать миграции схемы вручную (up делает это сам)
	docker compose run --rm migrator

build:
	cd shipper && cargo build --release
	cd policyd && go build ./...

test: rust-test go-test collector-test engine-test mcp-test triage-test rules-test ## Все тесты

rust-test:
	cd shipper && cargo test

go-test:
	cd policyd && go vet ./... && go test ./...

policy-test: ## Требует бинарник opa; go-test покрывает то же без него
	opa test policies -v

sample: ## Сгенерировать свежие демо-алерты за последний час (./sample, читает shipper)
	./scripts/gen-sample.sh

logs:
	docker compose logs -f collector engine shipper policyd

rules-test: ## Тесты правил корреляции на записанном трафике (rules/tests)
	./scripts/argus rules test

replay: ## Залить записанный трафик (august) и неделю субъектов (identity) в коллектор — демо инцидентов и паспортов
	./scripts/argus replay fixtures/events/august.ndjson
	./scripts/argus replay fixtures/events/identity.ndjson

collector-test:
	cd collector && go vet ./... && go test ./...

engine-test:
	cd engine && go vet ./... && go test ./...

mcp: ## Собрать локальный бинарник MCP-сервера (bin/argus-mcp) для Claude Code / Cursor
	cd mcp && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(APP_VERSION)" -o ../bin/argus-mcp .

mcp-test:
	cd mcp && go vet ./... && go test ./...

triage-test: ## Общий модуль редакции и точных фильтров (MCP, вебхук движка)
	cd triage && go vet ./... && go test -race ./...
