// dsh-mobile-access client half: a single phone icon in the sidebar footer
// (the official `sidebar.footer.action` seat, next to settings). Clicking it
// slides an in-page panel out from the right edge — no new tab, no navigation
// away. The panel hosts the setup page (/mobile-access) in an iframe so the
// QR/mode/pairing console lives exactly where the icon is.
// Plain hand-written __ModuleLoader__ bundle (no build step).
window.__ModuleLoader__.load({
	id: 'dsh-mobile-access',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		var React = require('react');

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
								background: '#101820',
								borderLeft: '1px solid #26323f',
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
									borderBottom: '1px solid #26323f',
									flex: 'none',
								},
							},
							React.createElement(
								'span',
								{ style: { color: '#e8ecf0', fontSize: '14px', fontWeight: 600, letterSpacing: '0.02em' } },
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
										color: '#8a97a5',
										fontSize: '20px',
										lineHeight: 1,
										padding: '0 4px',
									},
								},
								'\u00D7',
							),
						),
						React.createElement('iframe', {
							src: '/mobile-access',
							title: 'Mobile Access',
							style: { flex: 1, border: 'none', background: '#101820' },
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
