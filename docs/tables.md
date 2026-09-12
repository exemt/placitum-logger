# Таблицы ClickHouse

Позвоночник тонкий. Детали — в таблице находок, одной на всех инспекторов.
Байты тела в ClickHouse не кладём. Ответ апстрима не ждём.

## Зерно

| Таблица | Зерно | Живёт | Роль |
| --- | --- | --- | --- |
| `waf.audit` | `(node, ray, phase)` | месяцы | access-лог: время, запрос, решение модуля, указатель на тело |
| `waf.audit_finding` | то же + `inspector`, `finding_idx` | месяцы | что именно сработало внутри движка |
| `waf.log` | строка текста | дни | журнал процессов контура: `access_log` и `error_log` nginx, свой журнал инспекторов и сайдкаров |

Новый инспектор — ни DDL, ни ветки в логгере: находка уже унифицирована на
проводе (`messages/inspector-audit.schema.ts`),
правило CRS у modsec и класс уязвимости у vlai ложатся в одни и те же
`{code, severity, target, rule}`. Своё движка едет в `engine` строкой JSON —
по нему смотрят, когда запись уже нашли, а не фильтруют.

Таблица на инспектора означала бы одну и ту же схему, размноженную по DDL, и
«найди все находки по правилу» как `UNION` по всем спутникам, растущий вместе
с их числом.

Карточка инцидента — два запроса по одному `ray`, склейка на чтении. Дашборд
«deny за час» читает только `waf.audit` и находок не открывает.

Ключ — `ray`, UUID запроса, а не `rid`: слот воркера повторяется на каждой ноде
и переиспользуется после освобождения, поэтому склеивать по нему события разных
источников нельзя. Модуль его агенту и не отдаёт.

## `waf.audit` — позвоночник

Только то, что знает модуль. Без `inspectors_json`, без текста CRS,
без `matched[]`. Живая схема — [schema/024_audit_v4.sql](../schema/024_audit_v4.sql)
(колонки набирались с [008](../schema/008_audit_v3.sql) по 021, в 024 таблица
пересоздана целиком ради ключа); здесь она с пояснениями.

```sql
CREATE TABLE waf.audit
(
    ts    DateTime64(3),          -- поступление запроса, ставит модуль
    node  LowCardinality(String),
    ray   String,
    phase LowCardinality(String),
    rev   UInt32,                 -- версия ReplacingMergeTree, всегда 0: дедуп по ключу

    client_ip   IPv6,
    client_port UInt16,
    server_ip   IPv6,
    server_port UInt16,
    tls_version LowCardinality(String),
    tls_sni     String,

    method        LowCardinality(String),
    scheme        LowCardinality(String),
    host          String,
    uri           String,
    http_version  LowCardinality(String),
    args_size     UInt32,
    headers_size  UInt32,
    headers_count UInt16,
    body_size     UInt64,
    content_type  LowCardinality(String),
    status        UInt16,

    server_name LowCardinality(String),   -- какая конфигурация сработала
    location    LowCardinality(String),

    verdict    LowCardinality(String),    -- что сделали
    code       LowCardinality(String),    -- почему; пусто ровно на allow
    verdict_by LowCardinality(String),    -- кто; ключ в inspectors

    score   Int32,
    deny_at Int32,
    shadow  Int32,

    waf_latency_us UInt32,

    inspectors            Array(LowCardinality(String)),
    inspectors_verdict    Map(LowCardinality(String), LowCardinality(String)),
    inspectors_state      Map(LowCardinality(String), LowCardinality(String)),
    inspectors_score      Map(LowCardinality(String), Int32),
    inspectors_latency_ms Map(LowCardinality(String), Float32),
    inspectors_role       Map(LowCardinality(String), LowCardinality(String)),
    inspectors_profile    Map(LowCardinality(String), LowCardinality(String)),

    vars Map(LowCardinality(String), String),

    store_headers String,
    store_args    String,
    store_body    String,

    headers_preview Map(LowCardinality(String), String),  -- срез запроса
    args_preview    Map(LowCardinality(String), String),
    body_preview    String,

    headers_preview_truncated Array(LowCardinality(String)),  -- чьи значения урезаны
    args_preview_truncated    Array(LowCardinality(String)),
    headers_preview_dropped   UInt16,                         -- пар выброшено целиком
    args_preview_dropped      UInt16,

    INDEX idx_body_preview lower(body_preview)
        TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4,
    INDEX idx_sessions_user sessions_user TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_markers markers TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ray ray TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_client_ip client_ip TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_sessions_id sessions_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_uri lower(uri) TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (ts, node, ray, phase, frame_direction, frame_seq)
TTL toDate(ts) + INTERVAL 90 DAY DELETE;
```

Ключ ведёт временем, а ключ склейки `(node, ray, phase, frame_direction,
frame_seq)` идёт следом целиком. Так было не всегда: до
[024](../schema/024_audit_v4.sql) ключ был только ключом склейки, и
при случайном `ray` каждый вопрос журнала читал окно целиком, а `FINAL` сливал
все куски партиции заново. Дедуп с `ts` в голове цел: время ставит модуль, и
повторная доставка несёт ту же строку. Почему какой индекс —
[search.md](search.md#индекс).

`verdict_by`, а не `by`: `BY` — ключевое слово SQL, и цитировать его в каждом
запросе дороже, чем один раз назвать колонку иначе.

Массив `inspectors` держим рядом с картами: `has(inspectors, 'modsec')` дешевле
`mapKeys`, а спрашивают именно так. В массиве только инспекторы — итог модуля
лежит в картах под ключом `module`, но в списке званых был бы шумом на каждой
строке.

Молчун виден в `inspectors_state`: `timeout` (спрашивали, не дождались),
`absent` (на subject нет подписчиков), `skipped` (не спрашивали — `sample=` или
разомкнутый предохранитель). Без этого `code = 'fail_timeout'` не отвечает на
вопрос, из-за кого.

Колонки полноты склейки на позвоночнике нет: «доехали ли до обменника детали
находок» — вопрос доставки, а не инцидента, и на записи он неразрешим. Кто
звал и кто промолчал, знает модуль, и это уже здесь: `inspectors` и
`inspectors_state`. Есть ли строки находок, видно из `waf.audit_finding` в тот
момент, когда туда посмотрели, — см. [009](../schema/009_audit_drop_completeness.sql).

Локаторы обменника — строки JSON: их форму задаёт драйвер хранилища и меняет
вместе с собой, а фильтровать по ним никто не будет. По ключу из локатора
достают тело, когда запись уже нашли.

Превью — обратная задача, поэтому и колонки другие. Локатор отвечает на
«достать содержимое этого запроса», превью — на «найти все запросы с таким
заголовком»: карта отвечает на это точным сравнением вместо разбора строки на
каждой строке таблицы. Объём задаёт конфигурация модуля
(`waf_preview` (`nginx/module/directives.md`)), а не клиент, поэтому колонка
не растёт от заголовка на мегабайт. Повторяющееся имя логгер склеивает через
`", "` — по правилу составных заголовков, а не выбором одного из двух; имена
заголовков приведены к нижнему регистру, имена параметров нет (`userId` и
`userid` для приложения разные).

Тело — строка, и ищут в нём подстроку. Индекс поставлен на `lower(body_preview)`,
и запрос обязан повторить это выражение: `LIKE` по `lower(...)` его включает,
`positionCaseInsensitive` — нет, для планировщика это другая функция.

Урезанное значение названо по имени. Пока секция обрывалась только целыми
парами, признак был не нужен: `headers_count` и `args_size` описывают сам
запрос, и превью сравнивалось с ними. Второй размер `waf_preview` ставит потолок
на отдельную пару, и на вопрос «этот `user-agent` полон?» сравнение с
`headers_count` уже не отвечает — длина карты прежняя, а значение префикс.
Отсюда `headers_preview_truncated` и `args_preview_truncated`: списки имён, чьи
значения урезаны. Список, а не пометка внутри значения — пометка попала бы в
поиск по содержимому, а ищут именно по нему; см.
[011](../schema/011_audit_preview_truncated.sql).

Выброшенные пары — счётчиками `headers_preview_dropped` и
`args_preview_dropped`. Пара выбрасывается, когда имя заняло больше половины
потолка, и перечислять такие имена значило бы записать ровно то, из-за чего пара
и не поместилась. Число отвечает на единственный разрешимый здесь вопрос: полна
ли секция.

С телом сравнение работает, только когда тело кто-то просил: `body_size` — это
размер того, что модуль положил в обменник, и на маршруте, где тело прочитано
одним `waf_preview body`, там ноль. Дальше этого превью о теле ничего не
обещает: оно и есть всё, что о теле известно записи.

Поиск по правилу — не здесь. `code` — это ветка решения модуля, закрытый набор
из восьми значений. CRS `913100` при блоке по порогу живёт в
`waf.audit_finding`.

### Сессии: `sessions_*`

Секция `sessions` записи ([019](../schema/019_audit_sessions.sql))
— чьи сессии назвали инспекторы: своя калитка отдаёт субъект токена, разбор
чужого JWT — claims, подсмотренная сессия приложения — логин из списка
доверенных. Параллельные массивы, а не строка JSON, в отличие от `actions` и
`rewrite`: по сессиям фильтруют — `has(sessions_user, 'alice')` — и `has()`
по массиву отвечает на это без разбора строки на каждой строке таблицы.
`i`-й элемент каждого массива — одна запись: `sessions_by` (инспектор),
`sessions_source`, `sessions_kind` (`own` / `jwt` / `app`), `sessions_user`,
`sessions_id`, `sessions_verified`, `sessions_issued`, `sessions_expires`,
`sessions_groups`, `sessions_passive`. Префикс `sessions_`, не `session_`:
`session_*` — итог соединения WebSocket, это другая вещь.

`sessions_id` — не кука: `sid` своей сессии, claim или отпечаток JWT, хеш
куки приложения. Пустые массивы — обычное состояние: калитки на маршруте нет
либо клиент пришёл без сессии.

```sql
-- всё, что делала alice за сутки, по любой калитке
SELECT ts, host, uri, verdict FROM waf.audit FINAL
WHERE has(sessions_user, 'alice') AND ts > now() - INTERVAL 1 DAY;

-- сессии, открытые без проверки подписи (alg none)
SELECT count() FROM waf.audit FINAL
WHERE arrayExists((k, v) -> k = 'jwt' AND v = 0, sessions_kind, sessions_verified);

-- кто ходил чаще всех: личность -- пара «источник:логин», не голый логин
SELECT arrayJoin(arrayDistinct(arrayFilter(x -> x != '',
    arrayMap((s, u) -> if(u = '', '', concat(s, ':', u)),
             sessions_source, sessions_user)))) AS session_user,
    count() AS hits, countIf(verdict = 'deny') AS denied
FROM waf.audit FINAL WHERE ts > now() - INTERVAL 1 DAY
GROUP BY session_user ORDER BY hits DESC;
```

Логин без источника — не личность: `alice` своей калитки и `alice` из чужого
JWT совпадают именем и больше ничем, пространство имён задаёт источник входа.
Поэтому и панель, и `by=user` группируют по паре, а `user=` фильтра принимает
обе формы ([search.md](search.md#поиск-по-сессиям)).

### Маркеры: `markers`

Секция `markers` записи ([020](../schema/020_audit_markers.sql)) —
метки, которые попросили поставить инспекторы глаголом `mark`
(`inspector-actions.md`). Строку называет
оператор в профиле отправителя; по дороге её никто не толкует.

Массив `Array(LowCardinality(String))` с bloom-индексом, а не строка JSON, в
отличие от `actions` и `rewrite`: по маркерам и фильтруют (`has(markers,
'bot-farm')`), и группируют (`arrayJoin(markers)`), а строк этих на весь контур
десятки — их пишет человек, а не запрос.

Кто поставил метку, в колонке нет: маркеры — множество (одна и та же метка от
двух инспекторов даёт один элемент), а отправитель и повод видны в `actions`
той же записи. Пустой массив — обычное состояние.

```sql
-- всё, помеченное bot-farm, за сутки
SELECT ts, client_ip, host, uri, verdict FROM waf.audit FINAL
WHERE has(markers, 'bot-farm') AND ts > now() - INTERVAL 1 DAY;

-- каких меток сколько: запись без меток в группировку не попадает
SELECT arrayJoin(markers) AS marker, count() AS hits FROM waf.audit FINAL
WHERE ts > now() - INTERVAL 1 DAY GROUP BY marker ORDER BY hits DESC;
```

### Страна и ASN словарями

Колонок под них в позвоночнике нет, и не будет. Страну и ASN знает не модуль,
а каталог пространства (`ip_countries`, `ip_asns` в Postgres контроллера) —
тот же, который оператор заливает `npm run load-geo`, из которого компилируются
паки инспектора адреса и из которого отвечает карточка адреса в панели.
Колонка на записи была бы четвёртой копией этих данных и отвечала бы только на
то, что записано после её появления.

Вместо неё — два словаря `IP_TRIE`, которые ClickHouse читает из того же
Postgres: [022_geo_country_dict.sql](../schema/022_geo_country_dict.sql)
и [023_geo_asn_dict.sql](../schema/023_geo_asn_dict.sql). Адрес
контура и учётка приходят логгеру окружением (`POSTGRES_HOST` и соседи) и
подставляются в текст миграции: инфраструктурным адресам в файле схемы не
место.

```sql
-- топ стран за сутки; адрес вне каталога даёт пустой код -- своя группа
SELECT dictGetOrDefault('waf.geo_country', 'code', client_ip, '') AS country,
       count() AS hits
FROM waf.audit FINAL
WHERE ts > now() - INTERVAL 1 DAY
GROUP BY country ORDER BY hits DESC;

-- всё с одной автономной системы
SELECT ts, client_ip, host, uri, verdict FROM waf.audit FINAL
WHERE dictGetOrDefault('waf.geo_asn', 'asn', client_ip, toUInt32(0)) = 9009
  AND ts > now() - INTERVAL 1 DAY;
```

Считается на запросе, поэтому отвечает и на то, что записано до заливки
каталога, и переезд префикса к другому оператору виден сразу — ценой того, что
запись годовой давности покажет сегодняшнего владельца, а не тогдашнего. Плата
за это невелика: миллион префиксов — 70 МиБ и наносекунды на `dictGet`, топ
стран за сутки по 1.9 млн записей — 0.2 с. Обычный список словаря не касается
вовсе: условие и ось появляются в запросе, только когда о них спросили, —
поэтому недоступный Postgres ломает гео-запросы, а не журнал.

Пространство в источнике словаря не фильтруется: `waf.audit` контурная,
пространства в ней нет, а префикс принадлежит стране одинаково во всех.

## `waf.audit_finding` — находки

Одна строка на элемент `findings[]` сообщения `kind=inspector`. Живая схема —
[schema/006_audit_finding.sql](../schema/006_audit_finding.sql). Логгер пишет
позвоночник и находки одним сбросом — тем, в который попала выборка с шины.
Друг друга события не ждут: связывает их `ray`, и связывает на чтении.

Инспектор без находок всё равно даёт строку: `finding_idx` 0 с пустым `code`.
Иначе «не вызвали» и «вызвали, чисто» снова не различить.

```sql
CREATE TABLE waf.audit_finding
(
    ts    DateTime64(3),
    node  LowCardinality(String),
    ray   String,
    phase LowCardinality(String),
    rev   UInt32,

    inspector LowCardinality(String),
    profile   LowCardinality(String),
    verdict   LowCardinality(String),
    score     Int32,
    engine_ms Float32,

    finding_idx UInt16,                  -- позиция в findings[]
    code        LowCardinality(String),
    severity    LowCardinality(String),
    target      String,                  -- uri | args | body | header:<имя> | …
    rule        LowCardinality(String),  -- пусто у неправиловой находки
    offset      Int64,
    length      Int64,                   -- 0 — движок места не назвал
    confidence  Float32,                 -- 0 — шкала неприменима
    evidence    String,

    engine String,                       -- своё движка, JSON как прислал

    INDEX idx_rule rule TYPE bloom_filter GRANULARITY 4,
    INDEX idx_code code TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ray  ray  TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (ts, node, ray, phase, inspector, finding_idx, frame_direction, frame_seq)
TTL toDate(ts) + INTERVAL 90 DAY DELETE;
```

`finding_idx` в ключе сортировки не для порядка, а для различения: два
одинаковых по `code` и `rule` совпадения в одном событии — законная пара строк,
и без порядкового номера дедуп схлопнул бы их в одну.

`verdict`, `score`, `profile` и `engine_ms` повторяются на каждой строке находки
одного события. Это плата за то, что запрос по правилу читает одну таблицу:
находок на событие единицы, а спрашивают именно так.

```sql
-- по правилу
SELECT * FROM waf.audit_finding FINAL
WHERE rule = '913100' AND ts > now() - INTERVAL 1 DAY;

-- по профилю: что вообще ловит strict
SELECT inspector, code, count() FROM waf.audit_finding
WHERE profile = 'strict' AND ts > now() - INTERVAL 1 DAY
GROUP BY inspector, code ORDER BY count() DESC;

-- сироты: находка есть, запроса нет — промах сокета или мёртвый агент
SELECT f.ray FROM waf.audit_finding AS f FINAL
LEFT ANTI JOIN waf.audit AS a FINAL USING (node, ray, phase)
WHERE f.ts > now() - INTERVAL 1 HOUR;
```

`FINAL` у счёта и группировок обязателен: сорванный батч уезжает на повтор,
шина доставляет те же сообщения снова, и до слияния кусков в таблице лежат
обе копии строки. Список поиск читает без него — под `FINAL` ClickHouse 24.8
не умеет идти по порядку ключа и останавливаться на `LIMIT`, — а дубль
снимает на странице по ключу склейки; в ручных запросах с `LIMIT` по времени
это тот же выбор. Skip-индексы под `FINAL` в 24.8 выключены настройкой
`use_skip_indexes_if_final`; поиск и логгер включают её на соединении
(`internal/ch/ch.go`), в `clickhouse-client` её надо добавить самому:
`SETTINGS use_skip_indexes_if_final = 1`. Безопасно, потому что версий у строк
нет — `rev` всегда 0, дубль одинаков байт в байт.

`evidence` — цитата совпавшего фрагмента, до 256 байт, и это ввод клиента.
Инспекторы персональных данных её не шлют вовсе; если понадобится свой TTL на
цитаты, его можно дать этой колонке, не трогая позвоночник.

### Что лежит в `engine`

Колонка нетипизирована намеренно: это единственное место, где форму задаёт
движок, а не контур. Фильтровать по ней никто не будет — её читают, когда
запись уже нашли по правилу, коду или профилю.

| Инспектор | Что кладёт |
| --- | --- |
| `modsec` | `crs_anomaly_score`, `crs_threshold`, `crs_would_block` |
| `ip` | поколение снапшота `gen`, страна, сторона списка |
| `vlai` | распределение по классам CVSS, число токенов, устройство |

Понадобится агрегат по чему-то из `engine` — это материализованная колонка над
JSON, не новая таблица и не новая ветка в логгере.

## Карточка

Два запроса по одному ключу, а не JOIN: позвоночник и находки соединяются на
чтении и только тогда, когда карточку открыли.

```sql
SELECT ts, node, ray, verdict, code, verdict_by, score, deny_at,
       method, host, uri, status,
       inspectors_verdict, inspectors_state, inspectors_latency_ms
FROM waf.audit FINAL
WHERE node = 'edge-01' AND ray = '11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10';

SELECT inspector, finding_idx, code, severity, target, rule,
       offset, length, confidence, evidence, engine
FROM waf.audit_finding FINAL
WHERE node = 'edge-01' AND ray = '11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10'
ORDER BY phase, inspector, finding_idx;
```

Список в UX / «blocked by threshold» — одна `waf.audit`.
Раскрытие строки — второй запрос, не JSON с позвоночника.

Сырые конверты (`waf.audit_frag`) не пишем: пока форма находки одна на всех
инспекторов, replay повторил бы ровно то же разложение по колонкам.

## `waf.log` — журнал процессов

Не позвоночник и не его спутник: связать их нечем. В строке `access_log` нет
`ray`, а `error_log` пишется и там, где запроса не было вовсе — reload,
недоступный апстрим, ошибка разбора конфига. Строки самих процессов контура
(инспекторов, калиток) лежат здесь же и по той же причине: у события «профиль
не разобрался» запроса нет вовсе. Живая схема —
[schema/032_log_v2.sql](../schema/032_log_v2.sql) (колонки из
[013](../schema/013_log.sql), ключ новый), дорога до неё —
«Журнал процессов» платформы.

```sql
CREATE TABLE waf.log
(
    ts       DateTime64(3),           -- приём датаграммы агентом или запись процесса
    writer   LowCardinality(String),  -- кто записал: нода или машина процесса
    service  LowCardinality(String),  -- что за сервис: tag= директивы nginx или имя процесса
    severity LowCardinality(String),  -- уровень syslog
    text     String,                  -- сама строка

    INDEX idx_text lower(text)
        TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, writer, service)
TTL toDate(ts) + INTERVAL 14 DAY DELETE;
```

`MergeTree`, а не `ReplacingMergeTree`: естественного ключа у строки лога нет,
и дедуп по содержимому схлопнул бы две одинаковые строки одной миллисекунды в
одну. Отсюда же и отсутствие `FINAL` в запросах к ней.

Ключ сортировки ведёт временем, как у позвоночника
([032](../schema/032_log_v2.sql)): каждый вопрос журнала — окно, а
страница — последние строки окна. Прежний ключ `(writer, service, ts)` из 013
упорядочивал время только внутри пары, и `ORDER BY ts DESC LIMIT 32` читал
окно целиком вместе с `text`. Теперь страница читается с хвоста ключа и
останавливается на `LIMIT`. `writer` и `service` остались в хвосте ключа:
гранул они не отсекают, и фильтр по ним стоит чтения узкой
`LowCardinality`-колонки по окну. Текст ищется подстрокой, поэтому у него не
место в ключе, а ngram-индекс; запрос обязан повторить выражение индекса.

Стенд, 13.8 млн строк за сутки на двух ядрах, до и после:

| Запрос | было | стало |
| --- | --- | --- |
| страница за сутки | 1.1 с, 3.1 ГБ прочитано | 44 мс, 18 МБ |
| страница за неделю | 2.8 с, 7.2 ГБ | 95 мс, 38 МБ |
| сотая страница | 0.95 с | 77 мс |
| страница с фильтром узла, уровня или подстроки | 150–220 мс | 150–180 мс |
| счёт за сутки | 49 мс | 14 мс |
| наборы фильтров (`facets`) | 0.54 с | 0.39 с |

Страница с фильтром и `facets` упираются в чтение колонки фильтра по окну, а
не в ключ.

```sql
-- ошибки этой ноды за час
SELECT ts, service, severity, text FROM waf.log
WHERE writer = 'edge-01' AND severity IN ('error', 'crit', 'alert', 'emerg')
  AND ts > now() - INTERVAL 1 HOUR
ORDER BY ts DESC;

-- подстрока: LIKE по lower(text), иначе idx_text не включится
SELECT ts, writer, text FROM waf.log
WHERE lower(text) LIKE '%upstream timed out%'
  AND ts > now() - INTERVAL 1 DAY
ORDER BY ts DESC;

-- что писали все реплики одного инспектора
SELECT ts, writer, severity, text FROM waf.log
WHERE service = 'modsec' AND ts > now() - INTERVAL 1 HOUR
ORDER BY ts DESC;
```

TTL короче, чем у аудита: логи прирастают на порядок быстрее, а отвечают на
вопросы последних дней. Инцидент месячной давности разбирают по `waf.audit`,
где для этого есть всё.

## Тело: Redis сейчас, S3 потом

Горячий Redis — почтовый ящик волны. После вердикта модуль делает `DEL`.
К моменту записи ключа скорее всего нет. Логгер тело не читает и не
копирует.

```
вердикт → waf_archive request (async, when=deny) → S3 → DEL hot
```

| Поля | Смысл | Когда жив |
| --- | --- | --- |
| `body_*` | где инспектор читал | только волна |
| `archive_*` | копия для разбора | месяцы, lifecycle бакета |
| `body_sha256` / `body_size` | связь события с объектом | всегда |

Локально — MinIO в `deploy/`, тот же драйвер `s3`. Указатели живут на
позвоночнике: тело принадлежит запросу, не инспектору.

## Ответ: не ждать

Запись — одна фаза. `phase=response` (этап 7) — вторая строка
позвоночника и свои находки, тот же `ray`. Колонки `upstream_*` на
строке `phase=request` не заполняем.

```sql
SELECT * FROM waf.audit FINAL
WHERE node = 'edge-01' AND ray = '11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10'
ORDER BY phase;
```

## Что заполнится сегодня

| Куда | Сейчас |
| --- | --- |
| `waf.audit` | всё, что есть в `messages/agent.schema.ts`: ключ, адреса, TLS, http с размерами, маршрут, решение, карты участников, `vars`, локаторы |
| `waf.audit_finding` | всё, что есть в `messages/inspector-audit.schema.ts`: находки `modsec`, `ip`, `vlai` и своё движка в `engine` |
| `archive_*`, `upstream_*` | своих колонок пока нет: архив — этап тела, ответ — этап 7 |

Страна и ASN приезжают в `vars`: `waf_var country $geoip2_data_country_code`.
User-Agent, Referer, XFF, Accept-Language, Origin, Content-Type, Accept и
`request_id` лежат там же без объявления — стандартный набор модуля.
Своего geo у модуля нет и не будет — это работа стороннего модуля nginx.
