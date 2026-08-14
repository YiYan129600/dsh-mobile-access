// dsh-mobile-access client half: a minimal sidebar-footer entry so users
// discover the setup page from the DEFAULT web UI — no deep link memory.
// Plain hand-written bundle in the __ModuleLoader__ format (no build step).
window.__ModuleLoader__.load({
	id: 'dsh-mobile-access',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		var React = require('react');

		function MobileEntry(props) {
			return React.createElement(
				'a',
				{
					href: '/mobile-access',
					target: '_blank',
					rel: 'noreferrer',
					title: '手机接入 Mobile Access',
					'aria-label': '手机接入 Mobile Access',
					style: { cursor: 'pointer', textDecoration: 'none' },
				},
				props && props.wide ? '手机接入' : '\u{1F4F1}',
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
