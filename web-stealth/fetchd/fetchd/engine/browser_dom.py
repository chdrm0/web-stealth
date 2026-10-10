"""The DOM side of the browser session: what is interactive, and how to act on it.

Elements are numbered in DOM order and marked in the document itself, so a later
call addresses the same node the caller was shown rather than re-running a
selector that may now match something else. The numbering is rebuilt on every
snapshot, which is why the caller is told the page changed whenever it is.
"""

from __future__ import annotations

import json

#: What counts as interactive. Role-based selectors are included because a lot of
#: modern UIs are divs wearing a role, and `[tabindex]` catches the rest.
INTERACTIVE_SELECTOR = ", ".join(
    (
        "a[href]",
        "button",
        "input",
        "textarea",
        "select",
        "summary",
        'label[for]',
        '[role="button"]',
        '[role="link"]',
        '[role="textbox"]',
        '[role="searchbox"]',
        '[role="combobox"]',
        '[role="menuitem"]',
        '[role="tab"]',
        '[tabindex]:not([tabindex="-1"])',
        # A captcha checkbox lives inside a frame whose contents are closed to us,
        # but the frame occupies pixels. Listed, it becomes pressable by
        # coordinate — which is the only way to answer it as the widget itself.
        'iframe[src*="recaptcha"]',
        'iframe[src*="captcha"]',
    )
)

MARK_ATTRIBUTE = "data-dsh-idx"

#: A marked element can sit inside an open shadow root, and a query on `document`
#: does not descend into one: the listing would offer a form the action call then
#: cannot find. Closed roots stay closed — page script cannot read them either, so
#: this walk stops exactly where the platform stops. Dropped into every script
#: that marks or resolves a marked element; each defines `mark` before the marker.
SHADOW_JS = """
  // Bounded on purpose. These scripts run in the page's own world, where a
  // hostile page can replace the `shadowRoot` accessor with a getter that hands
  // out a fresh object every call. Real shadow trees are strictly nested and
  // cannot cycle, but a patched accessor can, and an unbounded walk here is a
  // hang until the operation budget runs out while the renderer grows.
  const MAX_SCOPES = 4000;
  const MAX_SCANNED = 120000;
  const shadowScopes = (root) => {
    const scopes = [root];
    const seen = new Set([root]);
    let scanned = 0;
    for (let i = 0; i < scopes.length; i += 1) {
      let hosts;
      try {
        hosts = scopes[i].querySelectorAll('*');
      } catch (error) {
        break;  // not a real node: a patched accessor handed us something else
      }
      for (const host of hosts) {
        scanned += 1;
        if (scanned > MAX_SCANNED) return scopes;
        const shadow = host.shadowRoot;
        if (shadow && !seen.has(shadow)) {
          seen.add(shadow);
          if (scopes.length >= MAX_SCOPES) return scopes;
          scopes.push(shadow);
        }
      }
    }
    return scopes;
  };
  const markedByIndex = (index) => {
    const hits = [];
    for (const scope of shadowScopes(document)) {
      for (const el of scope.querySelectorAll(`[${mark}="${index}"]`)) {
        hits.push(el);
        // Two hits is already the refusal; walking further only proves that.
        if (hits.length > 1) return hits;
      }
    }
    return hits;
  };
"""

#: Where each script takes that helper. A marker rather than concatenation, so
#: the scripts stay readable top to bottom.
LOOKUP_MARKER = "/* shadow-lookup */"


def _with_lookup(script: str) -> str:
    """Expand the lookup marker. A script that lost its marker fails loudly: the
    numbering would silently stop reaching shadow content."""
    if LOOKUP_MARKER not in script:
        raise ValueError("the page script has no shadow-lookup marker")
    return script.replace(LOOKUP_MARKER, SHADOW_JS)

#: Runs in the page. Returns the numbered elements plus enough page identity for
#: the caller to notice that it is looking at something else than before.
#:
#: The payload is stringified on purpose: nodriver asks CDP for deep
#: serialization, which leaves plain objects in `deep_serialized_value` as a list
#: of key/value pairs rather than a dict. A JSON string comes back intact.
SNAPSHOT_JS = """
(() => {
  const limit = %(limit)d;
  const mark = %(mark)s;
  /* shadow-lookup */
  // Cleared wherever they were left, shadow roots included: a stale mark would
  // answer a later lookup with the wrong node.
  for (const scope of shadowScopes(document)) {
    scope.querySelectorAll(`[${mark}]`).forEach((el) => el.removeAttribute(mark));
  }
  const out = [];
  const seen = new Set();
  let assigned = 0;
  // `truncated` has to come from the loop, not from the counter: a page with
  // exactly `limit` interactive elements was not cut, and telling the caller
  // otherwise trains it to ignore the notice when a list really is cut.
  let cut = false;
  // A page's own navigation is interactive too, and on a site like GitHub that
  // is forty elements of header before the first result. When the document has
  // a `main`, its elements are listed first and the rest of the page follows, so
  // the limit is spent on the content rather than on the chrome.
  const roots = [...document.querySelectorAll('main'), document];
  const interactiveIn = (scope, budget) => {
    // An open shadow root is a tree of its own: a control built inside one is
    // invisible to a query on the document, and the page would then be listed as
    // having nothing to act on. Bounded for the same reason as the scope walk,
    // and it stops collecting once the remaining limit is covered rather than
    // gathering the whole tree first.
    const found = [];
    const queue = [scope];
    const walked = new Set([scope]);
    let scanned = 0;
    for (let i = 0; i < queue.length; i += 1) {
      let nodes;
      try {
        nodes = queue[i].querySelectorAll('*');
      } catch (error) {
        break;
      }
      for (const el of nodes) {
        if (found.length >= budget) return found;
        scanned += 1;
        if (scanned > MAX_SCANNED) return found;
        if (el.matches(%(selector)s)) found.push(el);
        const shadow = el.shadowRoot;
        if (shadow && !walked.has(shadow) && queue.length < MAX_SCOPES) {
          walked.add(shadow);
          queue.push(shadow);
        }
      }
    }
    return found;
  };
  for (const root of roots) {
    if (cut) break;
    for (const el of interactiveIn(root, limit - out.length)) {
      if (out.length >= limit) { cut = true; break; }
      if (seen.has(el)) continue;
      seen.add(el);
      const box = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      if (box.width === 0 && box.height === 0) continue;
      assigned += 1;
      el.setAttribute(mark, String(assigned));
      const tag = el.tagName.toLowerCase();
      const text = (el.innerText || el.value || el.getAttribute('aria-label') ||
                    el.getAttribute('placeholder') || el.getAttribute('title') || '')
        .replace(/\\s+/g, ' ').trim().slice(0, 90);
      out.push({
        index: assigned,
        tag,
        // Every field is cut. The reply is one JSON line and the reader drops the
        // whole connection over a long one, so a page that plants a 40 KB `name`
        // on a hundred fields must not be able to take the channel down.
        role: (el.getAttribute('role') || '').slice(0, 40),
        type: (el.getAttribute('type') || '').slice(0, 40),
        name: (el.getAttribute('name') || '').slice(0, 120),
        // The resolved property, not the attribute: a relative href is a trap for
        // a caller that cannot see the page. Cut, because a data: URL can be
        // megabytes and the answer travels as one JSON line.
        href: (typeof el.href === 'string' ? el.href : (el.getAttribute('href') || '')).slice(0, 300),
        // A password field is never echoed: the listing travels into the caller's
        // context, and a secret already in the page has no business following it.
        value: (tag === 'input' || tag === 'textarea') && !(tag === 'input' && (el.type || '').toLowerCase() === 'password')
          ? String(el.value || '').slice(0, 60) : '',
        text,
        disabled: Boolean(el.disabled),
        region: root === document ? 'page' : 'main',
      });
    }
  }
  return JSON.stringify({
    elements: out,
    truncated: cut,
    title: String(document.title || '').slice(0, 200),
    url: String(document.location.href || '').slice(0, 500),
    ready: document.readyState,
  });
})()
"""


def snapshot_script(limit: int) -> str:
    return _with_lookup(SNAPSHOT_JS) % {
        "limit": int(limit),
        "mark": json.dumps(MARK_ATTRIBUTE),
        "selector": json.dumps(INTERACTIVE_SELECTOR),
    }


#: One action on one numbered element. `type` uses the prototype setter because
#: React and friends keep their own copy of the value and ignore a bare
#: assignment to `el.value`. The answer is stringified for the same reason the
#: snapshot is.
ACT_JS = """
(() => {
  const index = %(index)d;
  const action = %(action)s;
  const value = %(value)s;
  const mark = %(mark)s;
  /* shadow-lookup */
  // Every scope is searched, and more than one hit is a refusal: a page is free
  // to carry its own data-dsh-idx on a decoy earlier in the document, and taking
  // the first match would then act on the decoy rather than on what the caller
  // was shown.
  const matches = markedByIndex(index);
  if (matches.length === 0) return JSON.stringify({ ok: false, reason: 'the element is no longer in the document' });
  if (matches.length > 1) return JSON.stringify({ ok: false, reason: 'this index is marked more than once; re-read the state' });
  const el = matches[0];
  el.scrollIntoView({ block: 'center' });
  const tag = el.tagName.toLowerCase();
  if (action === 'click') {
    el.click();
    return JSON.stringify({ ok: true, tag, text: (el.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 90) });
  }
  if (action === 'type' || action === 'select') {
    if (tag === 'select') {
      el.value = value;
      // A value that matches no option leaves selectedIndex at -1: reporting that
      // as success would have the caller believe a choice was made.
      if (el.selectedIndex < 0) return JSON.stringify({ ok: false, reason: 'no option matches that value' });
      el.dispatchEvent(new Event('change', { bubbles: true }));
      const chosen = el.options[el.selectedIndex].text;
      return JSON.stringify({ ok: true, tag, text: chosen });
    }
    if (tag !== 'input' && tag !== 'textarea') {
      // The value setter belongs to input and textarea. Calling it on a
      // contenteditable or a role=textbox div throws "Illegal invocation", which
      // reaches the caller as an internal error rather than as a wrong target.
      return JSON.stringify({ ok: false, reason: `typing needs an input or textarea, this is a <${tag}>` });
    }
    const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value');
    if (setter && setter.set) setter.set.call(el, value); else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    if (tag === 'input' && (el.type || '').toLowerCase() === 'password') {
      // Confirmed without repeating it: the reply is kept in the caller's context.
      return JSON.stringify({ ok: true, tag, text: `${value.length} characters typed into the password field` });
    }
    return JSON.stringify({ ok: true, tag, text: String(el.value).slice(0, 60) });
  }
  if (action === 'submit') {
    const form = el.closest('form');
    if (!form) return JSON.stringify({ ok: false, reason: 'the element is not inside a form' });
    if (typeof form.requestSubmit === 'function') form.requestSubmit(); else form.submit();
    return JSON.stringify({ ok: true, tag: 'form', text: '' });
  }
  if (action === 'focus') {
    el.focus();
    return JSON.stringify({ ok: true, tag, text: '' });
  }
  return JSON.stringify({ ok: false, reason: `unsupported action ${action}` });
})()
"""

ACTIONS = frozenset({"click", "type", "select", "submit", "focus"})

#: Elements that carry a document of their own. Their contents are not in our DOM
#: — a cross-origin frame is closed to us — so the only way to press what is
#: inside one is to press where it is drawn. In practice this is the sign-in
#: button: Google hands sites a widget frame, and the button is not ours to click.
EMBEDDED_TAGS = frozenset({"iframe", "embed", "object"})

#: The marked element's tag and the centre of its visible box, so a real mouse
#: event can be sent to those coordinates instead of firing on the frame element.
BOX_JS = """
(() => {
  const mark = %(mark)s;
  /* shadow-lookup */
  const matches = markedByIndex(%(index)d);
  if (matches.length === 0) return JSON.stringify({ ok: false, reason: 'the element is no longer in the document' });
  if (matches.length > 1) return JSON.stringify({ ok: false, reason: 'this index is marked more than once; re-read the state' });
  const el = matches[0];
  el.scrollIntoView({ block: 'center' });
  const box = el.getBoundingClientRect();
  return JSON.stringify({
    ok: true,
    tag: el.tagName.toLowerCase(),
    x: Math.round(box.left + box.width / 2),
    y: Math.round(box.top + box.height / 2),
    width: Math.round(box.width),
    height: Math.round(box.height),
    // The frame's own address. Its contents are closed to us, but the URL in the
    // attribute is not, and it says whose session the press is about to use.
    src: String(el.src || el.data || el.getAttribute('src') || '').slice(0, 500),
  });
})()
"""


def box_script(index: int) -> str:
    return _with_lookup(BOX_JS) % {"index": int(index), "mark": json.dumps(MARK_ATTRIBUTE)}


#: What captcha machinery the page carries. The widget's contents are usually
#: closed to us, but the frame's `src` is an attribute of *this* document, and
#: reCAPTCHA puts the site key in it (`k=`). That key is what a solver needs.
CAPTCHA_JS = """
(() => {
  const widgets = [];
  const seen = new Set();
  const add = (w) => {
    if (!w || !w.sitekey || seen.has(w.sitekey)) return;
    seen.add(w.sitekey);
    widgets.push(w);
  };
  document.querySelectorAll('.g-recaptcha[data-sitekey]').forEach((el) => add({
    sitekey: el.getAttribute('data-sitekey'),
    kind: el.getAttribute('data-size') === 'invisible' ? 'recaptcha-v2-invisible' : 'recaptcha-v2',
    source: 'div',
  }));
  for (const frame of document.querySelectorAll('iframe')) {
    const src = frame.src || frame.getAttribute('src') || '';
    if (!/recaptcha/i.test(src)) continue;
    let url;
    try { url = new URL(src, location.href); } catch (e) { continue; }
    const key = url.searchParams.get('k') || url.searchParams.get('co');
    // `anchor` is the checkbox frame; `bframe` is the puzzle behind it. The key
    // is the same, and one entry per key is enough. Enterprise is a different
    // API, not a variant: its token is bought as a different task type.
    const enterprise = /enterprise/i.test(url.pathname);
    const kind = (/anchor/.test(url.pathname) ? 'recaptcha-v2'
      : (/bframe/.test(url.pathname) ? 'recaptcha-v2-frame' : 'recaptcha'))
      + (enterprise ? ' (enterprise)' : '');
    add({
      sitekey: key,
      kind,
      enterprise,
      source: 'iframe',
      frame: url.pathname.slice(0, 60),
      query: url.search.slice(0, 300),
      // On Google's own pages the anchor carries a per-challenge token in `s=`,
      // and that is the `data-s` value the solver has to be given: without it the
      // task describes a different challenge than the one on screen.
      dataS: url.searchParams.get('s') || '',
    });
  }
  // Google's own widgets carry a second token, `data-s`, that the solver has to
  // be given alongside the site key — without it the answer it buys is for a
  // different challenge than the one on screen.
  const dataS = [...document.querySelectorAll('[data-s]')]
    .map((el) => el.getAttribute('data-s'))
    .filter((v) => v && v.length > 0)
    .slice(0, 2)
    .map((v) => v.slice(0, 200));
  const fields = [...document.querySelectorAll('textarea#g-recaptcha-response, textarea[name="g-recaptcha-response"]')];
  // Where the answer has to land varies by site: a textarea, or a hidden input
  // the page's own script fills (Google's challenge calls it `ca`).
  const answerFields = [...document.querySelectorAll('textarea, input[type="hidden"]')]
    .filter((el) => /^(ca|g-recaptcha-response|g-recaptcha-token|recaptcha-response|recaptcha_token)$/i.test(el.id || el.name || ''))
    .slice(0, 8)
    .map((el) => `${el.tagName.toLowerCase()}#${el.id || el.name}`);
  const api = window.recaptcha;
  return JSON.stringify({
    ok: true,
    pageUrl: location.href,
    widgets: widgets.slice(0, 5),
    dataS,
    answerFields,
    responseFields: fields.length,
    filled: fields.some((f) => (f.value || '').length > 0),
    hasGrecaptcha: typeof grecaptcha !== 'undefined',
    hasEnterpriseApi: typeof grecaptcha !== 'undefined' && Boolean(grecaptcha.enterprise),
    // Google's own sign-in challenge does not read the textarea: its frame calls
    // `recaptcha.challengeCompleted`. Where that exists, it is the door.
    hasChallengeCallback: Boolean(api && typeof api.challengeCompleted === 'function'),
    // A v3 widget has no checkbox at all; it is rendered through `?render=`.
    v3Render: (new URLSearchParams(location.search).get('render') || '').slice(0, 60),
  });
})()
"""

#: Put a solved token where the page expects it. Which of these exist depends on
#: the site; every one that answered is reported, and a failure is reported as a
#: failure rather than swallowed.
CAPTCHA_INJECT_JS = """
(() => {
  const token = %(token)s;
  const applied = [];
  const isAnswer = (el) => /^(ca|g-recaptcha-response|g-recaptcha-token|recaptcha-response|recaptcha_token)$/i.test(el.id || el.name || '');
  // The host page is where the answer lives: the widget frame writes into it.
  // Which element that is varies by site — a textarea for the public API, a
  // hidden input the page's own script fills for Google's sign-in challenge.
  for (const el of [...document.querySelectorAll('textarea, input[type="hidden"]')].filter(isAnswer)) {
    el.value = token;
    applied.push(`${el.tagName.toLowerCase()}#${el.id || el.name}`);
  }
  const api = window.recaptcha;
  if (api && typeof api.challengeCompleted === 'function') {
    try {
      api.challengeCompleted({ ca: token, as: '' });
      applied.push('recaptcha.challengeCompleted');
    } catch (e) {
      applied.push('recaptcha.challengeCompleted failed: ' + String(e).slice(0, 120));
    }
  }
  const g = typeof grecaptcha !== 'undefined' ? grecaptcha : null;
  const enterprise = g ? g.enterprise : null;
  for (const ns of (enterprise && typeof enterprise.injectResponse === 'function') ? [enterprise] : [g]) {
    if (ns && typeof ns.injectResponse === 'function') {
      try {
        ns.injectResponse(document.getElementById('g-recaptcha-response'), token);
        applied.push(ns === enterprise ? 'grecaptcha.enterprise.injectResponse' : 'grecaptcha.injectResponse');
      } catch (e) {
        applied.push('grecaptcha.injectResponse failed: ' + String(e).slice(0, 120));
      }
    }
  }
  return JSON.stringify({ ok: applied.length > 0, applied });
})()
"""


def captcha_script() -> str:
    return CAPTCHA_JS


def captcha_inject_script(token: str) -> str:
    # The token is passed as a JSON string, never spliced as bare source.
    return CAPTCHA_INJECT_JS % {"token": json.dumps(token)}


def act_script(index: int, action: str, value: str) -> str:
    if action not in ACTIONS:
        raise ValueError(f"unsupported browser action {action!r}")
    return _with_lookup(ACT_JS) % {
        "index": int(index),
        "action": json.dumps(action),
        "value": json.dumps(value or ""),
        "mark": json.dumps(MARK_ATTRIBUTE),
    }
