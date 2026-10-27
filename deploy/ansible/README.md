# Развёртывание ARGUS через Ansible

Роль `roles/argus` разворачивает стек на хосте, где уже стоит Docker с плагином compose
(Ubuntu 24.04, Debian 12/13). Она нейтральна к инфраструктуре: не ставит Docker, не трогает
фаервол и sshd — это роли вашего контура. Что делает: кладёт код (`git` или `rsync` рабочей копии),
создаёт тома данных ClickHouse на отдельном каталоге, генерирует `.env` со секретами прямо на хосте
(`scripts/argus init`), поднимает стек `make up`, ждёт консоль и коллектор, ставит cron бэкапа.

```sh
# inventory.yml
all:
  children:
    argus:
      hosts:
        argus1: { ansible_host: 192.168.0.126, ansible_port: 2202, ansible_user: ansible }

# group_vars/argus.yml — см. roles/argus/defaults/main.yml
argus_source: git
argus_repo_url: https://github.com/<org>/argus.git
argus_version: v1.0.0
argus_with_wazuh: false
argus_analyst_profile: mock

ansible-playbook -i inventory.yml deploy/ansible/argus.yml -l argus1
```

**Образы из реестра релиза** вместо сборки на хосте: `argus_images: registry`,
`argus_version: v1.0.0` (тег релиза — версия образов берётся из `VERSION` в выкачанном коде),
`argus_image_prefix: ghcr.io/<owner>/argus`; роль ставит `cosign`, проверяет подписи по `cosign.pub`
из репозитория, делает `docker login` (`argus_registry_user`, `argus_registry_token` с правом
`read:packages`, нужен только для приватных пакетов) и `make deploy`. Для приватного репозитория
код выкачивается с `argus_git_token` (право чтения содержимого).

Переход стенда с rsync-копии на `argus_source: git`: роль сама превращает каталог в checkout
(`git init`, `fetch`, `reset --hard <тег>`), `.env` и тома не трогаются.

Приватный репозиторий или стенд без доступа к Git-серверу: `argus_source: local`,
`argus_local_src: /path/to/argus` — код уезжает `rsync` с управляющей машины
(нужна коллекция `ansible.posix`).

Повторный прогон обновляет код и перезапускает только изменившиеся сервисы; `.env` существующие
значения не меняет, новые переменные дописывает. Переключить модуль Wazuh или профиль LLM —
поменять `argus_with_wazuh` / `argus_analyst_profile` и прогнать снова; для `on-prem-strict`
обязателен `ARGUS_LLM_LOCAL_ENDPOINT` в `argus_env`.

Полный конвейер «ВМ → харденинг → Docker → ARGUS» в этой роли не описан намеренно: создание ВМ,
пользователи, sshd, ufw и Docker у каждой организации свои. Подключите роль к своему плейбуку через
`ANSIBLE_ROLES_PATH=…:/path/to/argus/deploy/ansible/roles` и поставьте её последней. Порты, которые
должен пропускать фаервол: 8443/tcp (консоль), 8089/tcp (вебхуки и NDJSON), 5514/tcp+udp и
6514/tcp (syslog), 2055/udp (NetFlow). Docker публикует их на всех интерфейсах, поэтому хост должен
быть без публичного адреса либо за внешним фаерволом.

После прогона: пароль `admin` — `docker compose --project-directory /opt/argus exec web cat
/data/admin-password.txt`; первая проверка — `./scripts/api-smoke.sh` на хосте; источники — раздел
«Коллекторы и правила» в корневом README.
