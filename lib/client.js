// dsh-mobile-access client half: a single phone icon in the sidebar footer.
// Clicking it slides an in-page panel out from the right edge that hosts the
// setup page (/mobile-access) in an iframe.
//
// Theme sync: the panel chrome lives in the parent document and uses DSH
// design tokens (--dsw-alias-*) directly. The iframe is a separate document
// that cannot see those variables, so the panel resolves the token values
// and forwards them via postMessage; a MutationObserver re-sends on every
// theme/skin change. The setup page maps them onto its own palette.
window.__ModuleLoader__.load({
	id: 'dsh-mobile-access',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		var React = require('react');

		// Collapsed sidebar ("rail" mode) stacks footer entries vertically by
		// design; the user wants the phone icon beside settings. Scope a small
		// override to the rail footer buttons only (substring matchers track
		// the CSS-module naming convention without hardcoding the hash prefix).
		(function injectRailCss() {
			try {
				var id = 'dsh-mobile-access-rail-css';
				if (document.getElementById(id)) return;
				var tag = document.createElement('style');
				tag.id = id;
				tag.textContent =
					'[class*="_rail"] [class*="footerButtons"]{flex-direction:row !important;align-items:center;justify-content:center;gap:2px}';
				document.head.appendChild(tag);
			} catch (e) {}
		})();

		function cssVar(name, fallback) {
			try {
				var value = window.getComputedStyle(document.documentElement).getPropertyValue(name);
				return value && value.trim() ? value.trim() : fallback;
			} catch (e) {
				return fallback;
			}
		}

		function themePayload() {
			var dark =
				document.documentElement.getAttribute('data-ds-dark-theme') !== null ||
				document.documentElement.style.colorScheme === 'dark';
			var fallback = dark ? '#101820' : '#f4f6f9';
			return {
				type: 'dsh-theme',
				dark: dark,
				colors: {
					bg: cssVar('--dsw-alias-bg-base', fallback),
					panel: cssVar('--dsw-alias-bg-layer-2', cssVar('--dsw-alias-bg-layer-1', dark ? '#18222d' : '#ffffff')),
					line: cssVar('--dsw-alias-border-l2', cssVar('--dsw-alias-border-l1', dark ? '#26323f' : '#dfe4ea')),
					text: cssVar('--dsw-alias-label-primary', dark ? '#e8ecf0' : '#1c2430'),
					muted: cssVar('--dsw-alias-label-secondary', dark ? '#8a97a5' : '#5c6675'),
					brand: cssVar('--dsw-alias-brand-primary', '#4d6bfe'),
					ok: cssVar('--dsw-alias-state-success-primary', '#3fbf7f'),
					warn: cssVar('--dsw-alias-state-warn-primary', '#ffb02e'),
					err: cssVar('--dsw-alias-state-error-primary', '#e5604e'),
					code: cssVar('--dsw-alias-markdown-code-block', dark ? '#0c141b' : '#eef1f5'),
				},
			};
		}

		function PhoneGlyph() {
			return React.createElement(
				'svg',
				{ width: 16, height: 16, viewBox: '0 0 16 16', fill: 'none', 'aria-hidden': true },
				React.createElement('path', {
					d: 'M4.6 1.8h6.8a.9.9 0 0 1 .9.9v10.6a.9.9 0 0 1-.9.9H4.6a.9.9 0 0 1-.9-.9V2.7a.9.9 0 0 1 .9-.9Zm0 9.9h6.8',
					stroke: 'currentColor',
					strokeWidth: 1.2,
					strokeLinecap: 'round',
				}),
			);
		}

		function MobileEntry() {
			var open = React.useState(false);
			var isOpen = open[0];
			var setOpen = open[1];
			var iframeRef = React.useRef(null);

			React.useEffect(
				function () {
					if (!isOpen) return;
					var frame = iframeRef.current;
					var send = function () {
						if (frame && frame.contentWindow) {
							frame.contentWindow.postMessage(themePayload(), '*');
						}
					};
					// Reply whenever the iframe page announces it is ready (its
					// script may start after our first send — that first send
					// would be lost on an unloaded document).
					var onMessage = function (e) {
						if (e.data && e.data.type === 'ma-ready') send();
					};
					window.addEventListener('message', onMessage);
					var observer = new MutationObserver(send);
					observer.observe(document.documentElement, {
						attributes: true,
						attributeFilter: ['data-ds-dark-theme', 'style'],
					});
					send();
					return function () {
						window.removeEventListener('message', onMessage);
						observer.disconnect();
					};
				},
				[isOpen],
			);

			var panel = null;
			if (isOpen) {
				panel = React.createElement(
					'div',
					{
						style: {
							position: 'fixed',
							inset: 0,
							zIndex: 10000,
							display: 'flex',
							justifyContent: 'flex-end',
							background: 'rgba(8,12,16,0.45)',
						},
						onClick: function (e) {
							if (e.target === e.currentTarget) setOpen(false);
						},
					},
					React.createElement(
						'div',
						{
							style: {
								width: 'min(600px, 94vw)',
								height: '100%',
								background: 'var(--dsw-alias-bg-layer-2, #18222d)',
								borderLeft: '1px solid var(--dsw-alias-border-l2, #26323f)',
								boxShadow: '-12px 0 32px rgba(0,0,0,0.4)',
								display: 'flex',
								flexDirection: 'column',
							},
						},
						React.createElement(
							'div',
							{
								style: {
									display: 'flex',
									alignItems: 'center',
									justifyContent: 'space-between',
									padding: '12px 16px',
									borderBottom: '1px solid var(--dsw-alias-border-l2, #26323f)',
									flex: 'none',
								},
							},
							React.createElement(
								'span',
								{
									style: {
										color: 'var(--dsw-alias-label-primary, #e8ecf0)',
										fontSize: '14px',
										fontWeight: 600,
										letterSpacing: '0.02em',
									},
								},
								'手机接入 · Mobile Access',
							),
							React.createElement(
								'button',
								{
									type: 'button',
									'aria-label': '关闭',
									title: '关闭',
									onClick: function () { setOpen(false); },
									style: {
										cursor: 'pointer',
										border: 'none',
										background: 'transparent',
										color: 'var(--dsw-alias-label-secondary, #8a97a5)',
										fontSize: '20px',
										lineHeight: 1,
										padding: '0 4px',
									},
								},
								'\u00D7',
							),
						),
						React.createElement('iframe', {
							ref: iframeRef,
							src: '/mobile-access',
							title: 'Mobile Access',
							onLoad: function () {
								// Loaded later than the panel's first send — resend.
								if (iframeRef.current && iframeRef.current.contentWindow) {
									iframeRef.current.contentWindow.postMessage(themePayload(), '*');
								}
							},
							style: {
								flex: 1,
								border: 'none',
								background: 'var(--dsw-alias-bg-layer-2, #18222d)',
							},
						}),
					),
				);
			}

			return React.createElement(
				React.Fragment,
				null,
				React.createElement(
					'button',
					{
						type: 'button',
						title: '手机接入 Mobile Access',
						'aria-label': '手机接入 Mobile Access',
						'aria-expanded': isOpen,
						onClick: function () { setOpen(!isOpen); },
						style: {
							cursor: 'pointer',
							border: 'none',
							background: 'transparent',
							padding: 0,
							color: 'inherit',
							display: 'inline-flex',
							alignItems: 'center',
							justifyContent: 'center',
						},
					},
					React.createElement(PhoneGlyph, null),
				),
				panel,
			);
		}

		function apply(ctx) {
			var slots = ctx.get('slots');
			if (slots === undefined) return;
			var disposeEntry;
			slots.inject('sidebar.footer.action', function () {
				disposeEntry = slots.register({ name: 'sidebar.footer.action', id: 'mobile-access' }, MobileEntry);
			});
			ctx.on('dispose', function () {
				if (disposeEntry) {
					try { disposeEntry(); } catch (e) {}
				}
			});
		}

		module.exports = { name: 'mobile-access', apply: apply };
		return module.exports;
	},
});
