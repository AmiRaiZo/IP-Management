(() => {
  let theme = '';
  try { theme = localStorage.getItem('ip-archive-theme') || ''; } catch (_) {}
  if (!theme) {
    const match = document.cookie.match(/(?:^|;\s*)ip-archive-theme=(dark|light)(?:;|$)/);
    theme = match ? match[1] : 'light';
  }
  document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
})();
