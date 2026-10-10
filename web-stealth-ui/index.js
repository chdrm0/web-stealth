/**
 * The host half of the settings page is a marker.
 *
 * Everything this package does happens in `client.js`. The row exists so the
 * browser module table has an entry to load and so the plugin appears in the
 * plugin list under its own title; it must not reach the retrieval stack, which
 * belongs to `@local/web-stealth` and is mounted once there.
 *
 * @module @local/web-stealth-ui
 */
const name = 'web-stealth-ui';
const inject = [];

function apply() {}

export { apply, inject, name };
