import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ResponsiveShellRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        cls.index = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
        cls.ip_form = (ROOT / "templates" / "ip_form.html").read_text(encoding="utf-8")
        cls.profile = (ROOT / "templates" / "profile.html").read_text(encoding="utf-8")
        cls.settings = (ROOT / "templates" / "settings.html").read_text(encoding="utf-8")
        cls.setup_2fa = (ROOT / "templates" / "setup_2fa.html").read_text(encoding="utf-8")
        cls.accounts = (ROOT / "templates" / "accounts.html").read_text(encoding="utf-8")
        cls.account_form = (ROOT / "templates" / "account_form.html").read_text(encoding="utf-8")
        cls.account_groups = (ROOT / "templates" / "account_groups.html").read_text(encoding="utf-8")
        cls.app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        cls.groups = (ROOT / "templates" / "groups.html").read_text(encoding="utf-8")
        cls.users = (ROOT / "templates" / "users.html").read_text(encoding="utf-8")
        cls.css = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
        cls.js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        cls.version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    def test_sidebar_toggle_is_outside_drawer_and_stays_fixed(self):
        toggle = self.base.index('id="sidebar-toggle"')
        sidebar = self.base.index('<aside class="sidebar">')
        self.assertLess(toggle, sidebar)
        self.assertIn(".sidebar-toggle{position:fixed!important", self.css)

    def test_mobile_drawer_overlays_without_reserving_page_width(self):
        self.assertIn(".main-column{width:100%!important;max-width:100%;min-width:0;margin:0!important}", self.css)
        self.assertIn("width:min(286px,calc(100vw - 56px))!important", self.css)
        self.assertIn("transform:translateX(calc(-100% - 8px));visibility:hidden;pointer-events:none", self.css)
        self.assertIn("body.mobile-sidebar-open .sidebar{transform:translateX(0);visibility:visible;pointer-events:auto", self.css)

    def test_mobile_menu_defaults_closed_and_does_not_reuse_desktop_preference(self):
        self.assertIn("window.matchMedia('(max-width: 720px)')", self.js)
        self.assertIn("document.body.classList.remove('sidebar-collapsed')", self.js)
        self.assertIn("document.body.classList.toggle('mobile-sidebar-open')", self.js)

    def test_narrow_viewport_canvas_cannot_shrink_to_half_width(self):
        self.assertIn("/* v3.0.5: override tablet sidebar width at mobile specificity from shrinking the mobile content column.", self.css)
        self.assertIn("html,body{width:100%;max-width:100%;min-width:0;margin:0;overflow-x:clip}", self.css)
        self.assertIn(".app-shell{position:relative;width:100%;max-width:100%;min-width:0}", self.css)
        # Must match the specificity of the tablet selector that sets width: calc(100% - 215px).
        self.assertIn(
            "body.has-sidebar:not(.sidebar-collapsed).main-column,body.has-sidebar.sidebar-collapsed.main-column,body.has-sidebar.main-column,body.sidebar-collapsed.main-column,.main-column{width:100%!important;min-width:0!important;max-width:100%!important;margin:0!important}",
            "".join(self.css.split())
        )
        self.assertIn(".container{width:calc(100%-20px)!important;max-width:100%!important", "".join(self.css.split()))
        self.assertIn(".global-theme-toggle{right:10px!important;top:10px!important;max-width:calc(100%-20px)}", "".join(self.css.split()))
        self.assertIn(".welcome-toast{top:58px;right:10px;left:auto;width:min(390px,calc(100%-20px))", "".join(self.css.split()))


    def test_mobile_ip_cards_include_direct_edit_and_delete_actions_for_admins(self):
        self.assertIn('class="mobile-ip-open" data-mobile-ip-card', self.index)
        self.assertIn('class="mobile-ip-edit" href="{{ url_for(\'ip_edit\', ip_id=ip.id) }}"', self.index)
        self.assertIn('action="{{ url_for(\'ip_delete\', ip_id=ip.id) }}"', self.index)
        self.assertIn('class="mobile-ip-actions"', self.index)
        self.assertIn("data-confirm=\"Delete this IP record?\"", self.index)
        self.assertIn(".mobile-ip-actions{display:flex!important", self.css)

    def test_table_column_icons_are_consistent_for_ip_and_accounts(self):
        self.assertGreaterEqual(self.index.count('class="column-icon'), 7)
        self.assertGreaterEqual(self.accounts.count('class="column-icon'), 5)
        for kind in ("profile", "name", "group", "ip", "port", "user", "key", "date"):
            self.assertIn(f"column-icon icon-{kind}", self.index)
        for kind in ("name", "group", "user", "email", "key", "date"):
            self.assertIn(f"column-icon icon-{kind}", self.accounts)
        self.assertIn(".column-heading{display:inline-flex", self.css)

    def test_mobile_ip_directory_uses_name_only_cards_and_blurred_details_dialog(self):
        self.assertNotIn("Keep connection details organized, searchable, and available to the right people.", self.index)
        self.assertIn('class="mobile-ip-list" data-mobile-ip-list', self.index)
        self.assertIn('class="mobile-ip-card" data-mobile-search-row', self.index)
        self.assertIn('class="mobile-ip-open" data-mobile-ip-card', self.index)
        self.assertIn('class="mobile-ip-edit"', self.index)
        self.assertIn('url_for(\'ip_delete\', ip_id=ip.id)', self.index)
        self.assertIn('name="csrf_token"', self.index)
        self.assertIn('id="mobile-ip-details-modal"', self.index)
        self.assertIn('id="mobile-ip-details-list"', self.index)
        self.assertIn('data-copy-value', self.index)
        self.assertIn(".mobile-ip-details-modal::backdrop{background:rgba(7,16,29,.52);backdrop-filter:blur(8px)", self.css)
        self.assertIn(".inventory-panel .table-scroll{display:none!important}", self.css)
        self.assertIn("event.target.closest('[data-copy-value]')", self.js)
        self.assertIn("if (card.hasAttribute('data-ip-password'))", self.js)
        self.assertIn("mobileRows.forEach(row =>", self.js)

    def test_mobile_ip_cards_are_centered_spaced_and_group_precedes_ip(self):
        self.assertIn('v3.0.7: center and polish mobile IP cards', self.css)
        css = "".join(self.css.split())
        self.assertIn('.mobile-ip-list{display:grid;gap:10px;padding:14px12px16px}', css)
        mobile_css = "".join(self.css[self.css.index('v3.0.7: center and polish mobile IP cards'):].split())
        self.assertIn('justify-content:center', mobile_css)
        self.assertIn('text-align:center', mobile_css)
        self.assertLess(self.index.index('icon-group'), self.index.index('icon-ip'))
        self.assertIn('class="column-heading"', self.index)
        self.assertIn('class="column-icon icon-key"', self.index)
        self.assertIn('class="column-heading"', self.accounts)
        self.assertIn('class="column-icon icon-email"', self.accounts)
        self.assertLess(self.js.index("addMobileIpDetail('Group', data.ipGroup, false)"),
                        self.js.index("addMobileIpDetail('IP address', data.ipAddress, true)"))

    def test_return_position_is_preserved_across_edits_and_deletions(self):
        self.assertIn("ip-archive-return-position", self.js)
        self.assertIn("function captureReturnPosition(source)", self.js)
        self.assertIn("function restoreReturnPosition()", self.js)
        self.assertIn("anchorIndex", self.js)
        self.assertIn("anchorOffset", self.js)
        self.assertIn("sessionStorage.removeItem(returnPositionKey)", self.js)
        self.assertIn('data-scroll-record="ip-{{ ip.id }}"', self.index)
        self.assertIn('data-scroll-record="group-{{ group.id }}"', self.groups)
        self.assertIn('data-scroll-record="user-{{ user.id }}"', self.users)
        self.assertIn("search: search?.value || ''", self.js)
        self.assertIn("group: group?.value || ''", self.js)

    def test_filtered_return_url_is_carried_through_ip_edit_and_delete(self):
        self.assertIn("function currentDirectoryReturnUrl()", self.js)
        self.assertIn("destination.searchParams.set('return_to', currentDirectoryReturnUrl())", self.js)
        self.assertIn("returnInput.value = currentDirectoryReturnUrl()", self.js)
        self.assertIn('name="return_to" value="{{ return_to|default(url_for(\'index\')) }}"', self.ip_form)

    def test_shared_authenticator_ui_does_not_advertise_per_user_enrollment(self):
        self.assertIn("All accounts use the same site Authenticator code.", self.users)
        self.assertIn("Shared Authenticator", self.users)
        self.assertIn("regular users do not set up a separate authenticator.", self.users)
        self.assertIn("users do not register a separate authenticator.", self.settings)
        self.assertIn("Shared Authenticator required", self.profile)
        self.assertIn("two_factor_mode == 'per_user' and user.totp_secret", self.profile)

    def test_mandatory_authenticator_setup_has_csrf_protected_logout(self):
        self.assertIn("url_for('cancel_2fa_setup')", self.setup_2fa)
        self.assertIn('name="csrf_token"', self.setup_2fa)
        self.assertIn(">Log out</button>", self.setup_2fa)
        self.assertIn("Two-factor authentication remains required.", self.setup_2fa)
        self.assertNotIn("url_for('settings')", self.setup_2fa)

    def test_account_vault_is_structurally_separate_from_ip_directory(self):
        self.assertIn("url_for('accounts')", self.base)
        self.assertIn("url_for('account_groups')", self.base)
        self.assertIn("ACCOUNT VAULT", self.base)
        self.assertIn("CREATE TABLE IF NOT EXISTS account_groups", self.app_source)
        self.assertIn("CREATE TABLE IF NOT EXISTS accounts", self.app_source)
        self.assertIn("REFERENCES account_groups(id)", self.app_source)
        self.assertIn("def safe_accounts_return_url", self.app_source)
        self.assertIn("def validate_account", self.app_source)
        self.assertIn('name="name" required', self.account_form)
        self.assertIn('name="username"', self.account_form)
        self.assertIn('name="email"', self.account_form)
        self.assertIn('name="password"', self.account_form)
        self.assertNotIn('name="username" required', self.account_form)
        self.assertNotIn('name="email" type="email" required', self.account_form)
        self.assertNotIn("{{ 'required' if not account else '' }}", self.account_form)
        self.assertNotIn("Only account groups appear here", self.account_form)
        self.assertNotIn("IP groups are not shared", self.account_form)
        self.assertIn("data-live-search", self.accounts)
        self.assertIn("data-group-filter", self.accounts)
        self.assertIn('data-scroll-record="account-{{ account.id }}"', self.accounts)
        self.assertIn('data-scroll-record="account-group-{{ group.id }}"', self.account_groups)
        self.assertIn("independent from IP groups", self.account_groups)
        self.assertIn("currentDirectoryReturnUrl()", self.js)
        self.assertIn("destination.pathname === '/accounts/new'", self.js)
        self.assertIn(r"^\/accounts\/\d+\/delete$", self.js)
        self.assertIn('class="mobile-account-list"', self.accounts)
        self.assertIn('class="btn btn-primary mobile-account-edit"', self.accounts)
        self.assertIn('>Edit account</a>', self.accounts)
        self.assertIn("account-inventory-panel .mobile-account-actions{display:flex!important", self.css)

    def test_account_form_only_requires_name_and_mobile_cards_show_edit(self):
        self.assertIn('name="name" required', self.account_form)
        self.assertNotIn('name="username" required', self.account_form)
        self.assertNotIn('name="email" type="email" required', self.account_form)
        self.assertNotIn("{{ 'required' if not account else '' }}", self.account_form)
        self.assertNotIn("Only account groups appear here; IP groups are not shared.", self.account_form)
        self.assertIn('class="btn btn-primary mobile-account-edit"', self.accounts)
        self.assertIn('>Edit account</a>', self.accounts)
        self.assertIn("account-inventory-panel .mobile-account-actions{display:flex!important", self.css)

    def test_assets_are_cache_busted_for_this_release(self):
        self.assertEqual(self.version, "3.0.22")
        self.assertIn("style.css') }}?v=3.0.22", self.base)
        self.assertIn("app.js') }}?v=3.0.22", self.base)


if __name__ == "__main__":
    unittest.main()
