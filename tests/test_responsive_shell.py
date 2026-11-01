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
        cls.login = (ROOT / "templates" / "login.html").read_text(encoding="utf-8")
        cls.accounts = (ROOT / "templates" / "accounts.html").read_text(encoding="utf-8")
        cls.account_form = (ROOT / "templates" / "account_form.html").read_text(encoding="utf-8")
        cls.account_groups = (ROOT / "templates" / "account_groups.html").read_text(encoding="utf-8")
        cls.notes = (ROOT / "templates" / "notes.html").read_text(encoding="utf-8")
        cls.notes_form = (ROOT / "templates" / "notes_form.html").read_text(encoding="utf-8")
        cls.note_groups = (ROOT / "templates" / "note_groups.html").read_text(encoding="utf-8")
        cls.app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        cls.groups = (ROOT / "templates" / "groups.html").read_text(encoding="utf-8")
        cls.users = (ROOT / "templates" / "users.html").read_text(encoding="utf-8")
        cls.css = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
        cls.js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        cls.version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        cls.release_workflow = (ROOT / ".github" / "workflows" / "publish-release.yml").read_text(encoding="utf-8")

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


    def test_mobile_ip_cards_include_inline_details_and_direct_edit_delete_actions(self):
        self.assertIn('class="mobile-ip-card" role="listitem"', self.index)
        self.assertIn('class="mobile-ip-fields"', self.index)
        self.assertNotIn("IP record #{{ ip.id }}", self.index)
        self.assertIn('class="mobile-ip-fields mobile-account-fields"', self.accounts)
        self.assertIn("mobile-ip-edit", self.index)
        self.assertIn("url_for('ip_edit', ip_id=ip.id)", self.index)
        self.assertIn("url_for('ip_delete', ip_id=ip.id)", self.index)
        self.assertIn('name="csrf_token"', self.index)
        self.assertIn('class="mobile-ip-actions"', self.index)
        self.assertIn('data-confirm="Delete this IP record?"', self.index)
        self.assertNotIn('id="mobile-ip-details-modal"', self.index)
        self.assertIn(".mobile-ip-actions{display:flex!important", self.css)


    def test_table_headers_are_simple_and_field_icons_are_aligned_with_values(self):
        self.assertNotIn('class="column-icon', self.index)
        self.assertNotIn('class="column-icon', self.accounts)
        self.assertIn('<th class="name-column">Name</th>', self.index)
        self.assertIn('<th>IP address / host</th>', self.index)
        self.assertIn("<th>Name</th>", self.accounts)
        self.assertIn("<th>Email</th>", self.accounts)
        self.assertIn('class="data-field-icon icon-ip"', self.index)
        self.assertIn('class="data-field-icon icon-user"', self.accounts)
        self.assertIn('class="data-field-icon icon-email"', self.accounts)
        self.assertIn(".data-field-icon svg{display:block", self.css)
        self.assertIn('html[data-theme="dark"] .data-field-icon', self.css)


    def test_mobile_ip_directory_uses_inline_details_cards_like_account_vault(self):
        self.assertNotIn("Keep connection details organized, searchable, and available to the right people.", self.index)
        self.assertIn('class="mobile-ip-list" data-mobile-ip-list', self.index)
        self.assertIn('class="mobile-ip-card" role="listitem"', self.index)
        self.assertIn('data-scroll-record="ip-{{ ip.id }}"', self.index)
        self.assertIn('class="mobile-ip-record-heading"', self.index)
        self.assertIn('class="mobile-ip-fields"', self.index)
        for label in ("IP address", "Port", "Username", "Password", "Notes", "Updated"):
            self.assertIn(f'class="mobile-data-label">{label}</span>', self.index)
        self.assertIn('data-copy-value="{{ ip.ip_address }}"', self.index)
        self.assertIn('data-copy-value="{{ ip.port }}"', self.index)
        self.assertIn('data-copy-value="{{ ip.username }}"', self.index)
        self.assertIn('data-copy-value="{{ ip.password_plain }}"', self.index)
        self.assertIn('class="mobile-ip-actions"', self.index)
        self.assertIn('class="mobile-account-list"', self.accounts)
        self.assertNotIn('class="mobile-data-row mobile-account-group-row"', self.accounts)
        self.assertIn('class="mobile-ip-card mobile-account-card"', self.accounts)
        self.assertIn('class="mobile-ip-fields mobile-account-fields"', self.accounts)
        self.assertIn('color: {{ card_group_color }} !important', self.accounts)
        self.assertIn('color: {{ card_group_color }} !important', self.index)
        self.assertIn('color: {{ group_color }} !important', self.groups)
        self.assertNotIn('id="mobile-ip-details-modal"', self.index)
        self.assertNotIn("mobileIpDetailsModal", self.js)
        self.assertIn("event.target.closest('[data-copy-value]')", self.js)
        self.assertIn("mobileRows.forEach(row =>", self.js)
        compact_css = "".join(self.css.split())
        self.assertIn(".mobile-ip-list{display:grid!important;gap:11px;padding:13px12px16px!important}", compact_css)
        self.assertIn(".mobile-ip-fields{display:grid;padding:3px14px6px}", compact_css)
        self.assertIn(".account-inventory-panel.mobile-account-list{display:grid!important;gap:10px;padding:13px12px16px!important}", compact_css)


    def test_mobile_ip_and_account_fields_use_clean_icons_and_simple_table_headers(self):
        self.assertIn("v3.0.7: center and polish mobile IP cards", self.css)
        compact_css = "".join(self.css.split())
        self.assertIn(".mobile-ip-list{display:grid!important;gap:11px;padding:13px12px16px!important}", compact_css)
        self.assertIn(".mobile-account-list{display:none}", compact_css)
        self.assertIn(".account-inventory-panel.mobile-account-list{display:grid!important;gap:10px;padding:13px12px16px!important}", compact_css)
        self.assertIn(".mobile-data-row{display:grid;grid-template-columns:27px92pxminmax(0,1fr)", compact_css)
        self.assertIn(".mobile-account-field{grid-template-columns:25px65pxminmax(0,1fr)", compact_css)
        self.assertNotIn('class="mobile-data-label">Group</span>', self.index)
        self.assertNotIn('class="mobile-data-label">Group</span>', self.accounts)
        self.assertNotIn('class="column-heading"', self.index)
        self.assertNotIn('class="column-heading"', self.accounts)


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
        self.assertIn("account_edit", self.app_source)
        self.assertIn("account_delete", self.app_source)
        self.assertIn('class="mobile-account-list"', self.accounts)
        self.assertIn("mobile-account-edit", self.accounts)
        self.assertIn(">Edit account</a>", self.accounts)
        self.assertIn("mobile-account-actions", self.accounts)
        self.assertIn(".account-inventory-panel .mobile-account-actions{display:flex!important", self.css)
        self.assertIn(".account-inventory-panel .mobile-account-list{display:grid!important;gap:10px;padding:13px 12px 16px!important}", self.css)


    def test_account_form_only_requires_name_and_mobile_cards_show_edit(self):
        self.assertIn('name="name" required', self.account_form)
        self.assertNotIn('name="username" required', self.account_form)
        self.assertNotIn('name="email" type="email" required', self.account_form)
        self.assertNotIn("{{ 'required' if not account else '' }}", self.account_form)
        self.assertNotIn("Only account groups appear here; IP groups are not shared.", self.account_form)
        self.assertIn('class="btn btn-primary mobile-account-edit mobile-ip-edit"', self.accounts)
        self.assertIn('>Edit account</a>', self.accounts)
        self.assertIn("account-inventory-panel .mobile-account-actions{display:flex!important", self.css)

    def test_v404_mobile_action_spacing_overrides_legacy_account_rules(self):
        self.assertIn(".mobile-ip-card > .mobile-ip-actions{margin-top:12px!important;padding:18px 12px 12px!important;gap:10px!important}", self.css)
        self.assertIn(".account-inventory-panel .mobile-account-card > .mobile-account-actions.mobile-ip-actions{margin-top:12px!important;padding:18px 12px 12px!important;gap:10px!important}", self.css)

    def test_group_color_controls_and_rendering_use_the_same_saved_color(self):
        self.assertNotIn("group-color-{{ (group.id or 0) % 8 }}", self.account_groups)
        self.assertNotIn("group-color-text-{{ (group.id or 0) % 8 }}", self.account_groups)
        self.assertIn('value="{{ group_color }}"', self.account_groups)
        self.assertIn('value="{{ group_color }}"', self.groups)
        self.assertIn(".group-list .group-symbol{color:var(--group-color)!important", self.css)
        self.assertIn(".group-list .group-name-text{color:var(--group-color)!important}", self.css)

    def test_assets_are_cache_busted_for_this_release(self):
        self.assertEqual(self.version, "4.1.0")
        self.assertIn("style.css') }}?v=4.1.0", self.base)
        self.assertIn("app.js') }}?v=4.1.0", self.base)

    def test_release_retention_uses_gh_cli_and_verifies_only_two_releases_remain(self):
        self.assertIn('"release", "list", "--limit", "100", "--json", "tagName,publishedAt"', self.release_workflow)
        self.assertIn('"release", "delete", tag, "--yes", "--cleanup-tag"', self.release_workflow)
        self.assertIn('if len(remaining) > 2:', self.release_workflow)
        self.assertIn('Release retention verification failed', self.release_workflow)

    def test_record_names_keep_normal_text_color_while_group_badges_use_selected_color(self):
        self.assertIn('<div class="mobile-ip-title"><strong>{{ ip.name or ip.ip_address or \'Unnamed IP\' }}</strong></div>', self.index)
        self.assertIn('<strong>{{ ip.name or \'Unnamed IP\' }}</strong><span class="group-tag"', self.index)
        self.assertIn('<div class="mobile-ip-title mobile-account-title"><strong>{{ account.name or account.username or account.email or \'Unnamed account\' }}</strong></div>', self.accounts)
        self.assertIn('<strong>{{ account.name or account.username or account.email or \'Unnamed account\' }}</strong><span class="group-tag"', self.accounts)
        self.assertNotIn('style="color: {{ card_group_color }} !important"', self.index)
        self.assertNotIn('style="color: {{ card_group_color }} !important"', self.accounts)
        self.assertNotIn('style="--group-color: {{ card_group_color }}"', self.index)
        self.assertNotIn('style="--group-color: {{ card_group_color }}"', self.accounts)
        self.assertIn('.mobile-ip-title>strong{color:var(--text)!important}', self.css)
        self.assertIn('.record-title>strong{color:var(--text)!important}', self.css)

    def test_notes_vault_is_separate_has_optional_composite_fields_and_fixed_cards(self):
        self.assertIn("url_for('notes')", self.base)
        self.assertIn("url_for('note_groups')", self.base)
        self.assertIn("NOTES VAULT", self.base)
        self.assertIn("CREATE TABLE IF NOT EXISTS note_groups", self.app_source)
        self.assertIn("CREATE TABLE IF NOT EXISTS notes", self.app_source)
        self.assertIn("REFERENCES note_groups(id)", self.app_source)
        self.assertIn("def validate_note", self.app_source)
        self.assertIn("def safe_notes_return_url", self.app_source)
        for field in ("title", "service_url", "ip_name", "ip_address", "ip_port", "ip_username", "ip_password",
                      "account_name", "account_username", "account_email", "account_password", "note_text"):
            self.assertIn(f'name="{field}"', self.notes_form)
            self.assertNotIn(f'name="{field}" required', self.notes_form)
        self.assertIn('for="service_url">Site (optional)</label>', self.notes_form)
        self.assertIn('<span class="note-field-label">Site</span>', self.notes)
        self.assertIn("data-live-search", self.notes)
        self.assertIn("data-group-filter", self.notes)
        self.assertIn('data-scroll-record="note-{{ note.id }}"', self.notes)
        self.assertIn("url_for('note_groups')", self.base)
        self.assertIn("COUNT(notes.id) AS note_count", self.app_source)
        self.assertIn(".notes-card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,340px),1fr))", self.css)
        self.assertIn(".note-card{height:500px;min-height:500px", self.css)
        self.assertIn(".note-card-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))", self.css)
        self.assertIn(".note-field-long{grid-column:1/-1", self.css)
        self.assertIn(".note-card-actions{height:54px;min-height:54px", self.css)
        self.assertIn("data-reveal-password", self.notes)
        self.assertIn("vault.encrypt(ip_password.encode", self.app_source)
        self.assertIn("vault.encrypt(account_password.encode", self.app_source)

    def test_ip_and_account_cards_hide_empty_fields_and_keep_compact_previous_geometry(self):
        ip_card = self.index.split('<article class="mobile-ip-card"', 1)[1].split("</article>", 1)[0]
        account_card = self.accounts.split('<article class="mobile-ip-card mobile-account-card"', 1)[1].split("</article>", 1)[0]
        for field in ("ip.port", "ip.username", "show_ip_passwords and ip.password_plain"):
            self.assertIn("{% if " + field + " %}", ip_card)
        for field in ("account.username", "account.email", "account.password_plain"):
            self.assertIn("{% if " + field + " %}", account_card)
        self.assertNotIn("<span class=\"muted\">—</span>", ip_card)
        self.assertNotIn("<span class=\"muted\">—</span>", account_card)
        self.assertIn("data-reveal-password", ip_card)
        self.assertIn("data-reveal-password", account_card)
        self.assertNotIn("inventory-fixed-card", self.index)
        self.assertNotIn("inventory-fixed-card", self.accounts)
        self.assertNotIn("inventory-fixed-card", self.css)
        self.assertIn(".mobile-ip-card{display:block", self.css)
        self.assertIn(".mobile-account-fields{display:grid", self.css)
        self.assertIn(".mobile-ip-actions{display:flex", self.css)

    def test_telegram_login_approval_screen_refreshes_and_has_no_bot_menu_action(self):
        self.assertIn("stage == 'approval'", self.login)
        self.assertIn("Waiting for approval", self.login)
        self.assertIn("This page checks for the decision automatically", self.login)
        self.assertIn("http-equiv=\"refresh\" content=\"3;url=", self.base)
        self.assertIn("url_for('login')", self.login)
        self.assertIn("elif action == \"ack_telegram_login\":", self.app_source)
        self.assertIn("Legacy audit callbacks are intentionally inert", self.app_source)
        self.assertNotIn('"text": "⌂ Menu", "callback_data": "menu"', self.app_source[self.app_source.index("def send_login_success_alert"):self.app_source.index("def send_login_failure_alert")])


if __name__ == "__main__":
    unittest.main()
