# web-stealth — каркас на review

Stealth-бэкенд для `web_fetch`: провайдер `ctx.web` + Python-sidecar на nodriver.
Ничего не установлено в профиль; это только каркас.

## 1. Поток данных

```
web_fetch(url)
  → dsh-tool-web            схема, timeoutMs, рендер, markdown, обрезка
  → ctx.web.fetch()         выбор провайдера (pin: fetchProvider)
  → StealthFetchProvider    id 'stealth-nodriver': policy → sidecar → shape-check
  → Sidecar (JS)            line-JSON поверх stdio, correlation by id
  → fetchd (Python)         nodriver: профиль cookies, ISP proxy, рендер
  → extract()               HTML → текст, до 200k символов
  ← WebFetchResult          { url, statusCode, body:{kind:'text',content}, truncated }
```

Один долгоживущий процесс браузера, одна вкладка на запрос.

## 2. Файлы

| Файл | Роль |
|---|---|
| [web-stealth/package.json](web-stealth/package.json) | манифест бандла, `dsh.bundle.patch` |
| [web-stealth/cordis.patch.yml](web-stealth/cordis.patch.yml) | монтирование плагина + перепин `fetchProvider` |
| [web-stealth/index.js](web-stealth/index.js) | регистрация провайдера, конфиг, shape-check ответа |
| [web-stealth/lib/sidecar.js](web-stealth/lib/sidecar.js) | супервизор процесса: handshake, RPC, cancel, restart |
| [web-stealth/lib/policy.js](web-stealth/lib/policy.js) | допуск URL |
| [fetchd/fetchd/protocol.py](fetchd/fetchd/protocol.py) | контракт фреймов и коды ошибок |
| [fetchd/fetchd/__main__.py](fetchd/fetchd/__main__.py) | цикл stdio, диспетч, отмена |
| [fetchd/fetchd/browser.py](fetchd/fetchd/browser.py) | nodriver: профиль, прокси, аргументы |
| [fetchd/fetchd/extract.py](fetchd/fetchd/extract.py) | HTML → текст |

## 3. Два patch-слоя — и почему конфиг переписан целиком

```yaml
- insert:
    - id: web-stealth
      name: '@local/web-stealth'
      config: {}
- id: web
  name: '@deepseek-ai/dsh-web'
  config:
    searchProvider: deepseek-official
    fetchProvider: stealth-nodriver
```

Loader заменяет `config` строки **целиком**, без deep-merge, поэтому
`searchProvider` продублирован ровно так, как его объявляет dsh-base
([dsh-base/cordis.patch.yml:471-473](../../../.nvm/versions/node/v24.21.0/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base/cordis.patch.yml#L471-L473)).

Слои не пересекаются: провайдеры живут на хосте, а сами инструменты — внутри
пресетов агента (хостовая строка `tool-web` в Web-профиле выключена). Поэтому
пресеты не трогаем: меняется только бэкенд.

**Риск, который надо принять.** Если плагин не активируется, пин на
`stealth-nodriver` даёт `WEB_PROVIDER_CONFIGURED_MISSING` и `web_fetch` падает
полностью — автоматического отката на `http` нет, потому что двух
доступных провайдера без пина шов считает неоднозначностью. Откат: вернуть
`fetchProvider: http` или удалить бандл.

## 4. Контракт провайдера

```
id        'stealth-nodriver'
available()   только локальные факты: живой дочерний процесс. Сеть запрещена контрактом.
fetch({url}, signal) → { url, statusCode, body: {kind:'text', content}, truncated }
```

`body.kind = 'text'`, а не `'html'`: `dsh-tool-web` режет тело по
`fetchMaxOutputChars` (200 000) **до** turndown, поэтому сырой post-JS HTML
тяжёлой страницы терял бы хвост ещё до конвертации. Извлечение идёт в Python,
бюджет контролируется там же.

Не-2xx — это результат, а не исключение: код отдаётся как есть, страница
блока прилетит текстом, а не ошибкой.

## 5. Протокол sidecar

Framing: одна JSON-строка на фрейм, stdout = только протокол, stderr = логи.
Лимит фрейма 4 MiB с обеих сторон.

| Направление | Фрейм |
|---|---|
| → | `{"op":"fetch","id":N,"url":"...","maxChars":200000,"timeoutMs":45000}` |
| → | `{"op":"cancel","id":N}` |
| → | `{"op":"shutdown"}` |
| ← | `{"op":"ready","version":"0.1.0","browser":"/usr/bin/google-chrome-stable"}` |
| ← | `{"id":N,"ok":true,"data":{"url","statusCode","text","truncated"}}` |
| ← | `{"id":N,"ok":false,"error":{"code","message"}}` |

Коды ошибок: `invalid-url`, `blocked-url`, `browser-start`, `navigation`,
`timeout`, `cancelled`, `unsupported-content`, `internal`.

`op:"event"` зарезервирован под прогресс и сейчас игнорируется.

## 6. Жизненный цикл

- **Ленивый старт.** Процесс поднимается на первом запросе, не при активации плагина.
- **Handshake 15 с.** Без `ready` — `handshake-timeout` с хвостом stderr.
- **Restart budget.** Не больше 3 рестартов за 5 минут, дальше — отказ, чтобы
  не гонять падающий браузер по кругу.
- **Отмена.** `AbortSignal` → `cancel` в sidecar + локальный reject. Python
  убивает задачу и не шлёт ответ.
- **Дедлайн.** Таймаут запроса считается в JS; Python держит свой `wait_for`
  как второй контур.
- **Shutdown.** `shutdown`, затем SIGTERM, затем SIGKILL через 3 с.
- **Форма ответа проверяется перед швом.** Пропущенное или переименованное поле
  падает loudly, а не уходит в `WebFetchResult` как `undefined`.

## 7. Безопасность

Уже сделано:
- Схема только `http`/`https`; URL ≤ 2048; credentials в URL запрещены —
  логин прокси живёт в переменой окружения, а не в аргументе модели.
- Литеральные приватные/loopback/link-local/CGNAT/multicast адреса отклоняются
  (v4 и v6, включая IPv4-mapped и NAT64).
- stderr-хвост в сообщениях об ошибках проходит redaction по `scheme://user:pass@`.
- Профиль браузера — вне репозитория, `$DSH_PROFILE_DIR/web-stealth/profile`,
  права `0700`.
- Логи только в stderr; значения cookies и прокси в протокол не попадают.

Не сделано и требует решения — см. O2.

## 8. Открытые точки

| # | Вопрос | Почему это блокирует |
|---|---|---|
| **O1** | `WebError` не импортируется | Бандл резолвит импорты из дерева профиля, где `@deepseek-ai/dsh-web` не гарантирован. Сейчас — локальный класс с `code`. Нужен ли настоящий `WebError` (structured error metadata в UI) или проверяем резолв `peerDependency`? |
| **O2** | SSRF через DNS | Литеральные приватные IP закрыты, но публичный хост, резолвящийся в `127.0.0.1`, — нет. Браузер нельзя «запинить» как штатный http-провайдер. Варианты: обязательный прокси, pre-resolution + `--host-resolver-rules`, или осознанный отказ. **Нужно твоё решение.** |
| **O3** | HTTP status из nodriver | В `browser.py` помечено TODO(verify): в 0.50.x плоские CDP-соединения, поверхность события main-document response надо подтвердить. Выдуманный 200 хуже отсутствующего кода. |
| **O4** | Стратегия ожидания | Сейчас просто `browser.get`. Нужны: wait на селектор, закрытие cookie-nag, скролл для lazy-load, обработка interstitial. Это и есть реальное качество извлечения. |
| **O5** | Формат текста | Сейчас plain text с маркерами заголовков и списков. Markdown-фидельity (таблицы, код, ссылки) — отдельный слой, пока не делаем. |

Отдельно: `nodriver` — AGPL-3.0. Для личной разработки норм, при
распространении это ограничение.

## 9. Точка расширения: поиск

Тот же контур, без изменений в протоколе процесса:

```
registerSearchProvider({ id: 'stealth-search', available, search })
→ {"op":"search","id":N,"query":"...","maxResults":8}
← {"id":N,"ok":true,"data":{"content":null,"sources":[{url,title,snippet,publishedAt}]}}
```

`WebSearchResult.content` отдавать можно — политика «не доверяем прозе
провайдера» принадлежит deepseek-провайдеру, а не шву. `maxResults` шв обрежет
сам. Патч: `searchProvider: stealth-search`. Селекторы SERP — отдельная задача,
их в каркасе нет.

## 10. Установка (не выполнялась)

```
plugin_manager: install_bundle → target = <абсолютный путь к web-stealth/>
uv venv --python 3.13 && uv sync           # внутри fetchd/
экспорт WEB_STEALTH_PROXY=...              # в окружение, из которого запущен хост
рестарт профиля                            # HMR не поднимает новую генерацию JS-модуля
```

После этого `web_fetch` идёт через браузер. Проверка: `Config.listConfigs` по
`@local/web-stealth` (статус строки) и живой `web_fetch` на JS-зависимой странице.

## 11. Что проверено, а что нет

Проверено: синтаксис всех JS-файлов (`node --check`); smoke-тест `policy.js`
(8 кейсов: приватные v4/v6, CGNAT, credentials, схема, мусор); компиляция всех
Python-файлов; smoke-тест `protocol.py` (валидные и битые фреймы, нормализация
неизвестного кода).

Не проверено: активация плагина в профиле; реальный резолв `@local/web-stealth`
из бандла; работа nodriver и получение status; поведение при кросс-доменных
редиректах; извлечение на живых страницах. Установка намеренно не выполнялась.
