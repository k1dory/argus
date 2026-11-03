### Правила

- `proxy-foreign-account` (a41c-net-077): имя учётки из одних Unicode-пробелов (NBSP, em space, U+3000 и т. п.) больше не даёт T1078. Проверка — класс «не `unicode.IsSpace`» вместо ASCII-`\S`.

### Коллектор

- `attrs.scope` и `post_nat`: пробелы вокруг IP-адреса обрезаются, как у `field|internal` в движке.
