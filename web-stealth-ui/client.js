/**
 * The settings page of the stealth web provider.
 *
 * It talks to its own plugin over the harness's HTTP carrier (`/api/stealth`),
 * which is the same origin the page was served from — see `lib/console.js` in the
 * provider package for why that is the whole authentication, and why the page
 * polls instead of holding a stream open.
 *
 * Controls are plain elements carrying theme tokens rather than the shipped
 * primitives: the primitive components' props are not part of a contract this
 * bundle can import, and a page that guesses at them breaks on their next
 * revision. Tokens are the contract — the host theme owns the colors.
 *
 * @module @local/web-stealth-ui/client
 */
window.__ModuleLoader__.load({
	id: '@local/web-stealth-ui',
	factory(require) {
		const React = require('react');
		const h = React.createElement;

		const NS = 'web-stealth-ui';
		const API = '/api/stealth';
		const STATE_POLL_MS = 2000;
		const PROGRESS_POLL_MS = 1000;
		// Offered for harvesting: origins where signing in changes what retrieval
		// can see. Brave search has no account and answers anonymously, so a
		// harvested set there buys nothing and only ages against the exit. It stays
		// a valid group when named in the plugin config.
		const HARVEST_GROUPS = ['google', 'github'];

		const DICTS = {
			en: {
				nav: 'Stealth web',
				title: 'Stealth web provider',
				subtitle: 'The exit used for retrieval, and the cookie sets it signs in with.',
				exit: 'Exit',
				exitScheme: 'Only a SOCKS5 proxy with proxy-side DNS is supported (socks5h). "No exit" sends this machine out as itself.',
				direct: 'No exit',
				directOn: 'No exit: retrieval and the browser leave as this machine itself, and the browser refuses requests aimed at this machine at its own network layer. A cookie set belongs to the exit it was harvested through.',
				browser: 'Browser',
				browserNone: 'No browser at the usual paths — name one in the plugin config.',
				browserHint: 'The same browser drives the browser tier and the login window. Switching it does not move the cookie set: a set belongs to the browser that harvested it.',
				exitHint: 'One exit for both: a cookie set that moves between addresses is what an identity provider reads as suspicious. The browser spelling is derived — Chrome has no socks5h.',
				exitClaims: 'Where the exit claims to be',
				noOverride: 'No override',
				noLocation: 'Send no location',
				claimsHint: 'The city and the clock belong to the exit, not to this machine. Empty sends nothing: the browser then reports this machine’s clock and no location at all. Change these together with the exit.',
				machineZone: 'This machine keeps ',
				apply: 'Apply',
				applied: 'Saved to the profile and applied; the sidecar restarts on the next request.',
				jar: 'Cookie sets',
				jarHint: 'Counts only — values never leave the jar file.',
				cookies: 'cookies',
				stale: 'refused',
				never: 'never written',
				ago: 'ago',
				harvest: 'Sign in and save',
				harvestHint: 'Opens a browser you can see on this machine. Log in there, then press “I am done”; the sets are written and reused by plain requests afterwards.',
				start: 'Start',
				finish: 'I am done',
				cancel: 'Cancel',
				running: 'Waiting for the login…',
				finished: 'Finished',
				error: 'Refused',
				captcha: 'Anti-Captcha key',
				captchaHint: 'The key a bought solve is paid with. An explicit key here wins over the project .env; an empty field keeps the .env fallback. A sidecar that is already running keeps its old environment — the new key is used from the next spawn.',
				captchaSet: 'Configured',
				captchaFallback: 'Not set here: the project .env key is in force',
				captchaNone: 'No key anywhere: a bought solve will be refused',
				captchaSave: 'Save key',
				captchaShow: 'Show',
				captchaHide: 'Hide',
				captchaClear: 'Clear',
				captchaSaved: 'Key saved to the profile; it reaches the sidecar through its environment only.',
				captchaCleared: 'Key cleared from the profile; the .env fallback answers again.',
			},
			ru: {
				nav: 'Stealth web',
				title: 'Stealth-провайдер сети',
				subtitle: 'Выход для запросов и наборы cookie, которыми он входит.',
				exit: 'Выход',
				exitScheme: 'Поддерживается только SOCKS5 с разрешением DNS на стороне прокси (socks5h). «Без выхода» означает, что машина отправляет запросы сама.',
				direct: 'Без выхода',
				directOn: 'Без выхода: запросы и браузер уходят как сама эта машина, а браузер сам отказывается обращаться к этой машине на сетевом уровне. Набор cookie принадлежит выходу, через который он был собран.',
				browser: 'Браузер',
				browserNone: 'В обычных путях браузер не найден — укажите его в конфигурации плагина.',
				browserHint: 'Один и тот же браузер ведёт и браузерную половину, и окно входа. Переключение не переносит набор cookie: набор принадлежит браузеру, в котором он был собран.',
				exitHint: 'Один выход на оба: набор cookie, который мигрирует между адресами, провайдеры входа читают как подозрительное поведение. Написание для браузера выводится — у Chrome нет socks5h.',
				exitClaims: 'Где, по утверждению браузера, находится выход',
				noOverride: 'Без переопределения',
				noLocation: 'Не отправлять координаты',
				claimsHint: 'Город и часы принадлежат выходу, а не этой машине. Пустое значение — ничего не отправлять: браузер сообщает часы этой машины и не сообщает местоположение. Менять вместе с выходом.',
				machineZone: 'Эта машина живёт по ',
				apply: 'Применить',
				applied: 'Сохранено в профиль и применено; сайдар поднимется на следующем запросе.',
				jar: 'Наборы cookie',
				jarHint: 'Только количество — значения из файла не выходят.',
				cookies: 'cookie',
				stale: 'отказ',
				never: 'не записан',
				ago: 'назад',
				harvest: 'Войти и сохранить',
				harvestHint: 'Открывает браузер на этой машине. Войдите там и нажмите «Я закончил»; наборы запишутся и дальше будут использоваться обычными запросами.',
				start: 'Запустить',
				finish: 'Я закончил',
				cancel: 'Отменить',
				running: 'Ожидание входа…',
				finished: 'Завершено',
				error: 'Отказ',
				captcha: 'Ключ Anti-Captcha',
				captchaHint: 'Ключ, которым оплачивается купленное решение. Явный ключ здесь важнее .env проекта; пустое поле оставляет запасной вариант из .env. Уже запущенный сайдар сохраняет старое окружение — новый ключ будет использован со следующего запуска.',
				captchaSet: 'Настроен',
				captchaFallback: 'Здесь не задан: действует ключ из .env проекта',
				captchaNone: 'Ключа нигде нет: покупка решения будет отклонена',
				captchaSave: 'Сохранить ключ',
				captchaShow: 'Показать',
				captchaHide: 'Скрыть',
				captchaClear: 'Очистить',
				captchaSaved: 'Ключ сохранён в профиль; он уходит только в окружение сайдара.',
				captchaCleared: 'Ключ удалён из профиля; снова действует запасной из .env.',
			},
		};

		const styles = {
			page: { display: 'flex', flexDirection: 'column', gap: 18, color: 'var(--dsw-alias-label-primary)', maxWidth: 720 },
			card: { display: 'flex', flexDirection: 'column', gap: 10, padding: 14, borderRadius: 10, border: '1px solid var(--dsw-alias-border-l1)', background: 'var(--dsw-alias-bg-layer-1)' },
			h2: { margin: 0, fontSize: 14, fontWeight: 600 },
			hint: { margin: 0, fontSize: 12, color: 'var(--dsw-alias-label-secondary)', lineHeight: 1.45 },
			warn: { margin: 0, fontSize: 12, color: 'var(--dsw-alias-state-warn-primary)', lineHeight: 1.45 },
			row: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' },
			label: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)', minWidth: 76 },
			mono: { fontFamily: 'ui-monospace, monospace', fontSize: 12 },
			input: { flex: '1 1 260px', padding: '7px 9px', borderRadius: 8, border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-base)', color: 'var(--dsw-alias-label-primary)', fontFamily: 'ui-monospace, monospace', fontSize: 12 },
			button: { padding: '7px 12px', borderRadius: 8, border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', cursor: 'pointer', fontSize: 12 },
			primary: { border: '1px solid var(--dsw-alias-brand-primary)', background: 'var(--dsw-alias-brand-primary)', color: 'var(--dsw-alias-bg-base)' },
			transcript: { margin: 0, padding: 10, borderRadius: 8, background: 'var(--dsw-alias-bg-base)', border: '1px solid var(--dsw-alias-border-l1)', maxHeight: 220, overflowY: 'auto', fontFamily: 'ui-monospace, monospace', fontSize: 11.5, whiteSpace: 'pre-wrap' },
			badge: { fontSize: 11, padding: '2px 6px', borderRadius: 6, border: '1px solid var(--dsw-alias-border-l1)' },
			table: { display: 'grid', gridTemplateColumns: '90px 1fr 1fr', gap: '4px 12px', fontSize: 12 },
		};

		async function call(path, body) {
			const response = await fetch(API + path, {
				method: body === undefined ? 'GET' : 'POST',
				headers: { 'content-type': 'application/json' },
				body: body === undefined ? undefined : JSON.stringify(body),
			});
			const data = await response.json().catch(() => ({}));
			if (!response.ok) throw new Error(data && data.error ? data.error : `HTTP ${response.status}`);
			return data;
		}

		function agoText(ms) {
			if (!ms) return null;
			const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
			if (minutes < 60) return `${minutes} min`;
			const hours = Math.round(minutes / 60);
			if (hours < 48) return `${hours} h`;
			return `${Math.round(hours / 24)} d`;
		}

		function Section({ t }) {
			const [state, setState] = React.useState(null);
			const [draft, setDraft] = React.useState(null);
			const [note, setNote] = React.useState('');
			// Drafts for the two claims that follow the exit. Null means "show what
			// is stored", so a poll never overwrites what someone is typing.
			const [tzDraft, setTzDraft] = React.useState(null);
			const [geoDraft, setGeoDraft] = React.useState(null);
			const [lines, setLines] = React.useState([]);
			const [picked, setPicked] = React.useState(() => Object.fromEntries(HARVEST_GROUPS.map((group) => [group, true])));
			// The solver's key is write-only: the stored value never comes back to
			// this page, so the draft is only what is being typed now, and "Show"
			// uncovers the draft, never a stored secret.
			const [keyDraft, setKeyDraft] = React.useState('');
			const [keyShown, setKeyShown] = React.useState(false);
			const cursor = React.useRef(0);
			const running = Boolean(state && state.harvest && state.harvest.running);

			// A poll error is stale the moment a poll succeeds; an error from a press
			// is not, and must not be wiped by the next poll two seconds later.
			const pollFailed = React.useRef(false);

			const refresh = React.useCallback(async () => {
				try {
					setState(await call('/state'));
					if (pollFailed.current) {
						pollFailed.current = false;
						setNote('');
					}
				} catch (error) {
					pollFailed.current = true;
					setNote(error.message);
				}
			}, []);

			React.useEffect(() => {
				void refresh();
				const timer = setInterval(() => void refresh(), STATE_POLL_MS);
				return () => clearInterval(timer);
			}, [refresh]);

			// The transcript is polled only while something is running: a finished
			// run keeps its lines, and a page reload re-reads them from the cursor.
			React.useEffect(() => {
				if (!running) return undefined;
				let stopped = false;
				const tick = async () => {
					if (stopped) return;
					try {
						const part = await call('/harvest/progress', { after: cursor.current });
						if (part.lines && part.lines.length > 0) {
							setLines((previous) => previous.concat(part.lines).slice(-200));
							cursor.current = part.next;
						}
					} catch {
						// A poll that failed is a poll to retry; the state poll shows
						// whether the run is still there.
					}
				};
				void tick();
				const timer = setInterval(() => void tick(), PROGRESS_POLL_MS);
				return () => {
					stopped = true;
					clearInterval(timer);
				};
			}, [running]);

			const act = React.useCallback(async (path, body) => {
				try {
					setNote('');
					await call(path, body ?? {});
					await refresh();
					return true;
				} catch (error) {
					pollFailed.current = false;
					setNote(error.message);
					return false;
				}
			}, [refresh]);

			// The field edits the address; the stored value is a URL. A value that is
			// not a socks5h exit (hand-edited elsewhere) is shown as it is, so the page
			// never claims a scheme it does not have.
			const currentProxy = state && state.proxy.startsWith('socks5h://') ? state.proxy.slice('socks5h://'.length) : (state ? state.proxy : '');
			const editing = draft === null ? currentProxy : draft;

			return h('div', { style: styles.page },
				h('div', {}, h('h2', { style: styles.h2 }, t('title')), h('p', { style: styles.hint }, t('subtitle'))),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('exit')),
					h('div', { style: styles.row },
						// The scheme is not editable: it is the part that carries the
						// remote-DNS rule, and the address is all anyone ever changes.
						h('span', { style: styles.mono }, 'socks5h://'),
						h('input', { style: styles.input, value: editing, spellCheck: false, placeholder: 'host:port', onChange: (event) => setDraft(event.target.value) }),
						h('button', { style: { ...styles.button, ...styles.primary }, onClick: () => act('/proxy', { proxy: `socks5h://${editing}` }).then((ok) => { if (ok) { setDraft(null); setNote(t('applied')); } }) }, t('apply')),
						h('button', { style: styles.button, onClick: () => act('/proxy', { proxy: '' }).then((ok) => { if (ok) { setDraft(null); setNote(t('applied')); } }) }, t('direct')),
					),
					h('p', { style: styles.hint }, t('exitScheme')),
					// With an exit, loopback is forced through it. Without one the
					// browser is refusing this machine instead, and that is worth
					// saying in the colour that means "pay attention".
					state && state.direct ? h('p', { style: styles.warn }, t('directOn')) : h('p', { style: styles.hint }, t('exitHint')),
				),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('exitClaims')),
					h('div', { style: styles.row },
						h('input', { style: styles.input, value: tzDraft === null ? ((state && state.timezone) || '') : tzDraft, spellCheck: false, placeholder: 'Europe/Helsinki', onChange: (event) => setTzDraft(event.target.value) }),
						h('button', { style: { ...styles.button, ...styles.primary }, onClick: () => act('/timezone', { timezone: tzDraft === null ? ((state && state.timezone) || '') : tzDraft }).then((ok) => { if (ok) { setTzDraft(null); setNote(t('applied')); } }) }, t('apply')),
						h('button', { style: styles.button, onClick: () => act('/timezone', { timezone: '' }).then((ok) => { if (ok) { setTzDraft(null); setNote(t('applied')); } }) }, t('noOverride')),
					),
					h('div', { style: styles.row },
						h('input', { style: styles.input, value: geoDraft === null ? ((state && state.geolocation) || '') : geoDraft, spellCheck: false, placeholder: '60.1699,24.9384', onChange: (event) => setGeoDraft(event.target.value) }),
						h('button', { style: { ...styles.button, ...styles.primary }, onClick: () => act('/geolocation', { geolocation: geoDraft === null ? ((state && state.geolocation) || '') : geoDraft }).then((ok) => { if (ok) { setGeoDraft(null); setNote(t('applied')); } }) }, t('apply')),
						h('button', { style: styles.button, onClick: () => act('/geolocation', { geolocation: '' }).then((ok) => { if (ok) { setGeoDraft(null); setNote(t('applied')); } }) }, t('noLocation')),
					),
					h('p', { style: styles.hint }, t('claimsHint')),
					// The override is meant to disagree with this machine — that is
					// the point of an exit. So the machine's own zone is stated as a
					// fact beside the claim, not as a warning: it is what tells you
					// when the claim stopped matching the exit you now have.
					state && state.timezone && state.machineTimezone && state.timezone !== state.machineTimezone
						? h('p', { style: styles.hint }, t('machineZone'), h('span', { style: styles.mono }, state.machineTimezone))
						: null,
				),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('browser')),
					h('div', { style: styles.row },
						...((state && state.browsers) || []).map((browser) => h('button', {
							key: browser.path,
							title: browser.path,
							style: state && state.browser === browser.path ? { ...styles.button, ...styles.primary } : styles.button,
							onClick: () => act('/browser', { browser: browser.path }).then((ok) => { if (ok) setNote(t('applied')); }),
						}, browser.name)),
						state && state.browsers && state.browsers.length === 0 ? h('span', { style: styles.warn }, t('browserNone')) : null,
					),
					h('p', { style: styles.hint }, t('browserHint')),
				),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('captcha')),
					h('div', { style: styles.row },
						// Masked by default; the placeholder is the stored key's mask,
						// never its value.
						h('input', {
							style: styles.input,
							type: keyShown ? 'text' : 'password',
							value: keyDraft,
							spellCheck: false,
							autoComplete: 'off',
							placeholder: state && state.antiCaptcha && state.antiCaptcha.present ? state.antiCaptcha.masked : '',
							onChange: (event) => setKeyDraft(event.target.value),
						}),
						h('button', { style: styles.button, onClick: () => setKeyShown(!keyShown) }, keyShown ? t('captchaHide') : t('captchaShow')),
						h('button', {
							style: { ...styles.button, ...styles.primary, opacity: keyDraft.trim().length === 0 ? 0.5 : 1 },
							disabled: keyDraft.trim().length === 0,
							onClick: () => act('/anticaptcha', { key: keyDraft }).then((ok) => { if (ok) { setKeyDraft(''); setKeyShown(false); setNote(t('captchaSaved')); } }),
						}, t('captchaSave')),
						h('button', { style: styles.button, onClick: () => act('/anticaptcha', { clear: true }).then((ok) => { if (ok) setNote(t('captchaCleared')); }) }, t('captchaClear')),
					),
					state && state.antiCaptcha ? h('p', { style: styles.hint }, state.antiCaptcha.configured ? `${t('captchaSet')}: ${state.antiCaptcha.masked} (${state.antiCaptcha.length})` : state.antiCaptcha.present ? t('captchaFallback') : t('captchaNone')) : null,
					h('p', { style: styles.hint }, t('captchaHint')),
				),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('jar')),
					h('div', { style: styles.table },
						h('span', { style: styles.label }, ''), h('span', { style: styles.label }, ''), h('span', { style: styles.label }, ''),
						...((state && state.jar) || []).map((entry) => h(React.Fragment, { key: entry.group },
							h('span', { style: styles.mono }, entry.group),
							h('span', {}, entry.count ? `${entry.count} ${t('cookies')}` : t('never')),
							h('span', { style: styles.label }, entry.updatedAt ? `${agoText(entry.updatedAt)} ${t('ago')}` : ''),
						)),
					),
					...((state && state.jar) || []).filter((entry) => entry.stale).map((entry) => h('span', { key: entry.group, style: { ...styles.badge, color: 'var(--dsw-alias-state-warn-primary)', width: 'fit-content' } }, `${entry.group}: ${t('stale')}`)),
					h('p', { style: styles.hint }, t('jarHint')),
				),

				h('section', { style: styles.card },
					h('h2', { style: styles.h2 }, t('harvest')),
					h('div', { style: styles.row },
						...HARVEST_GROUPS.map((group) => h('label', { key: group, style: { ...styles.mono, display: 'inline-flex', gap: 6, alignItems: 'center' } },
							h('input', { type: 'checkbox', checked: Boolean(picked[group]), onChange: (event) => setPicked({ ...picked, [group]: event.target.checked }) }),
							group,
						)),
					),
					h('div', { style: styles.row },
						h('button', {
							style: { ...styles.button, ...styles.primary, opacity: running ? 0.5 : 1 },
							disabled: running,
							onClick: () => {
								setLines([]);
								cursor.current = 0;
								void act('/harvest', { groups: HARVEST_GROUPS.filter((group) => picked[group]) });
							},
						}, t('start')),
						h('button', { style: styles.button, disabled: !running, onClick: () => void act('/harvest/finish') }, t('finish')),
						h('button', { style: styles.button, disabled: !running, onClick: () => void act('/harvest/cancel') }, t('cancel')),
						running ? h('span', { style: { ...styles.label, color: 'var(--dsw-alias-state-success-primary)' } }, t('running')) : null,
					),
					lines.length > 0 ? h('pre', { style: styles.transcript }, lines.join('\n')) : null,
					h('p', { style: styles.hint }, t('harvestHint')),
				),

				note ? h('p', { style: { ...styles.hint, color: 'var(--dsw-alias-state-error-primary)' } }, note) : null,
			);
		}

		return {
			inject: ['slots', 'locale'],
			apply(ctx) {
				// Registered before the seat: the section label is drawn by the shell
				// as soon as the registration lands.
				ctx.locale.register(NS, 'en', DICTS.en);
				ctx.locale.register(NS, 'ru', DICTS.ru);
				const t = ctx.locale.bind(NS);
				return ctx.slots.inject('settings.section', () => ctx.slots.register({
					name: 'settings.section',
					id: 'web-stealth',
					order: 60,
					label: () => t('nav'),
					locale: NS,
				}, (props) => h(Section, { ...props, t })));
			},
		};
	},
});
