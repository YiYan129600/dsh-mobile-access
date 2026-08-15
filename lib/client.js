// dsh-mobile-access client half: one phone icon in the sidebar footer
// (the official `sidebar.footer.action` seat, next to settings) that opens
// the setup page. No text link — icon only, styled with currentColor so it
// follows the shell theme. Plain hand-written __ModuleLoader__ bundle.
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
			return React.createElement(
				'button',
				{
					type: 'button',
					title: '手机接入 Mobile Access',
					'aria-label': '手机接入 Mobile Access',
					onClick: function () {
						window.open('/mobile-access', '_blank');
					},
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
