(() => {
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
      if (!window.confirm(form.dataset.confirm || 'Continue?')) event.preventDefault();
    });
  });
  const root = document.documentElement;
  const button = document.getElementById('theme-toggle');
  const icon = document.getElementById('theme-icon');
  const label = button?.querySelector('.theme-text');
  function paintTheme() {
    const dark = root.dataset.theme === 'dark';
    if (icon) icon.textContent = dark ? '☀' : '☾';
    if (label) label.textContent = dark ? 'Light mode' : 'Dark mode';
    if (button) button.setAttribute('aria-pressed', String(dark));
  }
  paintTheme();
  button?.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('ip-archive-theme', root.dataset.theme); } catch (_) {}
    paintTheme();
  });
  const search = document.querySelector('[data-live-search]');
  const group = document.querySelector('[data-group-filter]');
  const rows = [...document.querySelectorAll('[data-search-row]')];
  function filterRows() {
    const query = (search?.value || '').trim().toLowerCase();
    const groupName = group?.value || '';
    let count = 0;
    rows.forEach(row => {
      const visible = (!query || (row.dataset.search || '').toLowerCase().includes(query)) && (!groupName || row.dataset.group === groupName);
      row.hidden = !visible;
      if (visible) count++;
    });
    const counter = document.querySelector('[data-visible-count]');
    if (counter) counter.textContent = String(count);
    const empty = document.querySelector('[data-filter-empty]');
    if (empty) empty.hidden = count !== 0;
  }
  search?.addEventListener('input', filterRows);
  group?.addEventListener('change', filterRows);
  document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    try { await navigator.clipboard.writeText(target.value || target.textContent || ''); button.textContent = 'Copied'; }
    catch (_) { target.focus(); target.select?.(); }
  }));
})();
