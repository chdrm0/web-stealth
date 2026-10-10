# web-stealth — проект плагина

Цель: дать агенту доступ к вебу на локальной машине с жёстким бюджетом памяти
(~3 ГБ), где основной путь — дешёвый и быстрый, а браузер — дорогой резерв,
управляемый моделью.

## 1. Поток одного запроса

```
web_fetch(url)
  → seam provider 'stealth'
      1. policy: origin, схема, приватные адреса
      2. TIER 1  curl_cffi Session(impersonate='chrome150') + cookie-jar + SOCKS5
      3. classify outcome ── успех → extract → text+links → WebFetchResult
                             └ блок/капча/SPA-шелл/403/429 → TIER 2
      4. TIER 2  nodriver: lazy start, 1 вкладка, тот же jar и прокси,
                 пассивный рендер (navigate → wait → get_content) → extract
  → dsh-tool-web: шапка, trust-плашка, обрезка, spill
```

Браузерные команды модели — отдельная поверхность инструментов, она не проходит
через seam.

## 2. Два движка, один cookie-jar

Единый канонический магазин cookies на диске, нормализованные поля:
`name, value, domain, path, secure, httpOnly, sameSite, expires, partitionKey`.

| Направление | Механизм |
|---|---|
| браузер → store | `cdp.storage.get_cookies(browser_context_id)` → `List[network.Cookie]` |
| store → браузер | `cdp.storage.set_cookies([network.CookieParam…], browser_context_id)` |
| store → curl_cffi | `Session.cookies` из store перед запросом |
| curl_cffi → store | слияние `Set-Cookie` из ответа обратно в store |

Запись атомарная (`tmp` + `os.replace`), права `0600`, вне репозитория.

Смысл: один ручной логин в браузере даёт сессию обоим уровням; ответы curl
подогревают браузер, и наоборот. Context-скоуп CDP-методов совпадает с тем, как
устроен `cookie_mgr.load/save/release` по `browser_context_id`.

Оговорка: cookies ≠ отпечаток. Google и подобные связывают сессионную куку с
TLS/HTTP-фингерпринтом, поэтому jar обязателен, но не достаточен — отсюда
per-origin политика тиров.

## 3. Развилка: классификация исхода tier 1

Не «запрос упал», а разбор состояния.

| Исход tier 1 | Решение |
|---|---|
| 2xx + плотный текст | успех, в extract |
| 2xx + пустой shell / SPA-маркеры / `noscript` | tier 2 |
| 2xx + сигнатура challenges (captcha, consent wall, `Just a moment…`) | tier 2 |
| 403 / 429 / 503 | tier 2 (для 429 — сначала бэкдофф) |
| 401 | данные + пометка «нужна авторизация», tier 2 только если origin в allowlist |
| 404 / 410 | **данные**, не провал: seam отдаёт не-2xx как результат |
| сетевой провал / прокси отказ | ретрай с ограниченным экспоненциальным бэкдоффом и джиттером, затем tier 2 |
| таймаут | tier 2, с более длинным бюджетом |

Плюс конфиг по origin'ам: `force_browser: ["google.com"]`,
`curl_only: ["github.com"]`.

## 4. Прокси

`xray` SOCKS5 без авторизации, постоянно доступный локально, например
`socks5://127.0.0.1:1080`.

- `curl_cffi`: `proxy=` — SOCKS5 и SOCKS5H подтверждены (отказ соединения даёт
  `CurlError.code == 7`, а не `21 unsupported protocol`).
- `nodriver`: на старте `--proxy-server=…` или на контексте
  `browser.create_context(proxy_server=…)`; в 0.50.5 есть также
  `proxy_bypass_list` и `proxy_ssl_context`.
- Ротация выхода — опциональный хук, не часть контракта.

## 5. Формат вывода и защита контекста

Seam не принимает режим на вызове: `WebFetchRequest` = `{url}`. Поэтому режимы
разведены по разным инструментам.

| Инструмент | Что возвращает | Лимит inline |
|---|---|---|
| `web_fetch` (seam) | текст + ссылки | 12 000 символов |
| `web_raw(url)` | исходный документ | 60 000 символов, дальше spill |
| `browser_read()` | текст текущей страницы | 12 000 символов |

Опора на харнес: `spill-policy.maxInlineTokens: 12500` — вывод сверх порога
автоматически уходит в файл с путём в ответе, и его можно грепать. Это видно на
живом примере: PyPI-ответ был обрезан и сохранён в spill-файл. Значит сырой HTML
можно отдавать щедро, не забивая контекст мгновенно.

Extract: заголовки маркерами, списки, блоки-обёртки выкинуты (`script`, `style`,
`nav`, `footer`, оверлеи), ссылки отдельным списком `текст → href`.

## 6. Поверхность инструментов

Seam-провайдер:

```
web_fetch(url) → { url, statusCode, body:{kind:'text'}, truncated }
```

Браузерные инструменты (регистрация на `ctx.tools`, работают над «текущей
страницей», без session id — вкладка одна):

| Инструмент | Аргументы | Результат |
|---|---|---|
| `browser_open` | `url` | состояние страницы |
| `browser_state` | — | url, title, фрагмент текста, нумерованные элементы |
| `browser_find` | `text` или `selector` | совпадения с контекстом |
| `browser_links` | `filter?` | `текст → href` |
| `browser_act` | `index`, `action: click/type/scroll` | новое состояние |
| `browser_eval` | `js`, `await_promise?` | значение |
| `browser_close` | — | подтверждение |

Ключевой приём: **элементы возвращаются пронумерованными**, модель действует по
индексу, а не пишет XPath. Дёшево по токенам и не ломается от перебивки
классов. Реализация — `tab.select_all` + сериализация в индексную таблицу; для
текстовых поисков — `tab.find_all(text=…, timeout=)`, он же wait-условие.

## 7. Память и конкурентность

- Один браузер, одна вкладка, мьютекс на все браузерные операции.
- `curl_cffi` живёт постоянно (десятки МБ), браузер — только по требованию.
- Idle TTL браузера ~90 с, затем `browser.stop()`; при 3 ГБ и локальной GGUF-модели
  держать его тёплым расточительно.
- Жёсткий потолок одновременных curl-запросов (порядка 3).
- `web_fetch` в харнесе помечен concurrency-safe, поэтому сериализация обязана
  быть на стороне sidecar, а не полагаться на модель.

## 8. Что даёт харнес бесплатно

- spill сверх 12 500 токенов в файл (см. выше);
- `dsh-tool-call-timeout-policy`: для seam-фетча нужен `fetchTimeoutMs` порядка
  90 000 — браузерный рендер не влезает в дефолтные 30 000;
- карточки результата `web_fetch` и `WebFetchMeta` (url, statusCode, truncated);
- плашка `External web content follows…` на каждом выводе.

## 9. Этапы

| | Содержание | Проверка |
|---|---|---|
| **M1** | sidecar + `curl_cffi` tier 1 + cookie-store + SOCKS5 + extract | `web_fetch` через seam на github/brave |
| **M2** | классификатор исходов и per-origin политика | живые страницы блока, consent wall |
| **M3** | nodriver tier 2 пассивно: lazy start, jar, idle TTL, мьютекс | JS-зависимая страница |
| **M4** | браузерные инструменты с индексной моделью | цепочка open → state → act → read |
| **M5** | `web_search` provider на том же tier 1 | google/brave SERP → sources |

M1-M3 дают рабочий `web_fetch`. M4 — то, что превращает это в автоматизацию.

## 10. Риски и открытые вопросы

| # | Вопрос | Статус |
|---|---|---|
| R1 | `nodriver` ≥0.48 не импортируется: сырой `0xb1` в `cdp/network.py:1330` | **решено:** 0.50.5 + постинсталляционная правка байта. Правку оформить скриптом, иначе первый `uv sync` всё вернёт |
| R2 | Кто поднимает браузер для ручного логина | **снимается attach-режимом:** `Config(host=…, port=…)` → `connect_existing = True` (browser.py:313). Brave действительно поднимает CDP на `--remote-debugging-port` — проверено, `/json/version` ответил |
| R3 | Google поверх `chrome150` + cookies | не проверено; привязка куки к отпечатку и consent-состоянию |
| R4 | Профиль браузера и cookies = учётные данные | `0600`, вне репозитория, значения не попадают ни в логи, ни в вывод инструментов |
| R5 | SSRF | приватные литералы закрыты; публичный хост → приватный адрес не закрыт. При фиксированном локальном прокси риск ниже, но решение нужно |
| R6 | `find_all` принимает xpath/selector/text | **не подтверждается.** В 0.50.3 и 0.50.5 `find_all(text, timeout)` идентичны и идут в `cdp.dom.perform_search` — поиск по тексту, XPath ищется буквально. CSS → `select_all(…, include_frames=True)`, XPath → `xpath()` |
| R7 | Лицензия | `nodriver` — AGPL-3.0 |
| R8 | Прокси `<host>:<port>` | **решено, но с ловушкой.** Причина срывов — не прокси и не отпечаток, а IPv6: `socks5://` резолвит хост локально и передаёт прокси AAAA-адрес, который туннель не везёт → RST (curl 35). С `socks5h://` (резолв на прокси) все цели отдают 200 по HTTP/3; альтернатива — `IPRESOLVE=1`. **Плагин обязан использовать `socks5h://`.** Выход: `<адрес выхода>`, `<страна>`, `<ASN>` |
| R9 | Cookies из Brave по схеме yt-dlp | **не пройдёт:** в `Local State` нет `os_crypt.encrypted_key`, есть `os_crypt.portal` — ключ через XDG Portal Secret API. Расшифровка и не нужна: Brave расшифрует сам, снимаем через CDP |
| R10 | Расхождение отпечатков | Brave = Chrome/153.0.8010.37, tier 1 притворяется Chrome 150. Одни cookies с двух отпечатков — сами по себе сигнал. Нужен per-origin выбор уровня либо сглаживание |
| R11 | Память | 61 GiB всего, 3.7 GiB доступно. Одна вкладка — потолок, idle TTL обязателен |

## 12. Готовые механизмы nodriver 0.50.5, снимающие часть работы

`Browser.cookies` (`CookieJar`, `core/browser.py:651`):

- `get_all(requests_cookie_format=False)` → `List[cdp.network.Cookie]`; при `True`
  отдаёт `http.cookiejar.Cookie`, но тянет зависимость `requests` — не используем;
- `set_all(List[cdp.network.CookieParam])`;
- `save(file, pattern)` / `load(file)` — `pattern` регулярка по domain/key/value,
  «только google и github» это `pattern="(google|github)"`;
- `clear()`.

`save/load` — pickle CDP-формата: годится как браузерный бэкап, канонический store
для `curl_cffi` пишем сами (JSON, атомарная замена).

Прокси: `socks5://…` без авторизации — напрямую; с авторизацией — через
`util.ProxyForwarder` (`socks://user:pass@host:port`).

## 11. Проверенные факты

- `curl_cffi 0.16.3`: `chrome150` присутствует в `NATIVE_IMPERSONATE_TARGETS`
  (Chrome 150 / macOS Tahoe / `h3_fingerprints: True`); живой запрос ушёл по
  HTTP/3; SOCKS5 и SOCKS5H поддерживаются bundled libcurl `8.21.0-IMPERSONATE`.
- `FingerprintManager.update_fingerprints` + `api.impersonate.pro` — путь к более
  свежим отпечаткам, чем нативный набор.
- `nodriver 0.50.5`: `create_context(proxy_server=…, proxy_bypass_list=…,
  proxy_ssl_context=…)`; cookies — только через CDP
  (`cdp.storage.get_cookies` / `set_cookies` по `browser_context_id`); в `util`
  нет `load_cookies`/`save_cookies`, у `Tab` нет `get_all_cookies`/`set_all_cookies`.
- Харнес: `spill-policy.maxInlineTokens = 12500`.
