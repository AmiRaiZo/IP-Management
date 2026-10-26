import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ResponsiveShellRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
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
        self.assertIn("/* v3.0.3: prevent the tablet sidebar-width rule from shrinking the mobile content column.", self.css)
        self.assertIn("html,body{width:100%;max-width:100%;min-width:0;margin:0;overflow-x:clip}", self.css)
        self.assertIn(".app-shell{position:relative;width:100%;max-width:100%;min-width:0}", self.css)
        # Must match the specificity of the tablet selector that sets width: calc(100% - 215px).
        self.assertIn(
            "body.has-sidebar:not(.sidebar-collapsed).main-column,body.has-sidebar.sidebar-collapsed.main-column,body.has-sidebar.main-column,body.sidebar-collapsed.main-column,.main-column{width:100%!important;min-width:0!important;max-width:100%!important;margin:0!important}",
            "".join(self.css.split())
        )
        self.assertIn(".container{width:calc(100% - 20px)!important;max-width:100%!important", "".join(self.css.split()))
        self.assertIn(".global-theme-toggle{right:10px!important;top:10px!important;max-width:calc(100% - 20px)}", "".join(self.css.split()))
        self.assertIn(".welcome-toast{top:58px;right:10px;left:auto;width:min(390px,calc(100% - 20px))", "".join(self.css.split()))


    def test_assets_are_cache_busted_for_this_release(self):
        self.assertEqual(self.version, "3.0.3")
        self.assertIn("style.css') }}?v=3.0.3", self.base)
        self.assertIn("app.js') }}?v=3.0.3", self.base)


if __name__ == "__main__":
    unittest.main()
