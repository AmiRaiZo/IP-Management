(() => {
  document.querySelectorAll('[data-auto-dismiss]').forEach(toast => {
    const dismiss = () => {
      toast.classList.add('toast-leaving');
      window.setTimeout(() => toast.remove(), 220);
    };
    toast.querySelector('.welcome-toast-close')?.addEventListener('click', dismiss);
    window.setTimeout(dismiss, Number(toast.dataset.autoDismiss) || 2600);
  });
  const settingsNav = document.querySelector('.settings-nav[data-settings-tabs], .settings-nav[aria-label="Settings sections"]');
  if (settingsNav) {
    const tabLinks = [...settingsNav.querySelectorAll('[data-settings-tab]')];
    const sections = [...document.querySelectorAll('[data-settings-section]')];
    function activateSettingsTab(name, updateHash = true) {
      if (!sections.some(section => section.dataset.settingsSection === name)) name = 'branding';
      tabLinks.forEach(link => {
        const active = link.dataset.settingsTab === name;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      });
      sections.forEach(section => {
        const active = section.dataset.settingsSection === name;
        section.classList.toggle('is-active', active);
        section.hidden = !active;
      });
      if (updateHash && window.location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
    }
    tabLinks.forEach(link => link.addEventListener('click', event => {
      event.preventDefault();
      activateSettingsTab(link.dataset.settingsTab);
    }));
    activateSettingsTab(window.location.hash.slice(1), false);
  }
  document.querySelectorAll('[data-toggle-password]').forEach(toggle => {
    toggle.addEventListener('click', () => {
      const input = document.getElementById(toggle.dataset.togglePassword);
      if (!input) return;
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      toggle.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
      toggle.setAttribute('title', reveal ? 'Hide password' : 'Show password');
      toggle.classList.toggle('is-visible', reveal);
    });
  });
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
    document.cookie = `ip-archive-theme=${root.dataset.theme}; Max-Age=31536000; Path=/; SameSite=Lax`;
    paintTheme();
  });
  const checkUpdate = document.getElementById('check-update');
  checkUpdate?.addEventListener('click', async () => {
    const status = document.getElementById('update-status-text');
    const latestLine = document.getElementById('latest-version');
    const form = document.getElementById('apply-update-form');
    checkUpdate.disabled = true;
    checkUpdate.textContent = 'Checking…';
    if (status) status.textContent = 'Contacting GitHub and comparing versions…';
    if (form) form.hidden = true;
    if (latestLine) latestLine.hidden = true;
    try {
      const response = await fetch('/update/check', {headers: {'Accept': 'application/json'}, cache: 'no-store'});
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.error || 'GitHub could not be reached.');
      const currentLine = document.getElementById("current-version");
      if (currentLine) currentLine.textContent = result.current;
      if (status) status.textContent = result.message;
      if (latestLine) {
        latestLine.hidden = false;
        latestLine.textContent = `LATEST VERSION ${result.latest}`;
      }
      if (form && result.update_available) {
        form.hidden = false;
        document.getElementById('target-sha').value = result.latest_sha;
      }
    } catch (error) {
      if (status) status.textContent = error.message || 'Could not check for updates.';
    } finally {
      checkUpdate.disabled = false;
      checkUpdate.textContent = 'Check again';
    }
  });
  const updateModal = document.getElementById('update-modal');
  const applyUpdateForm = document.getElementById('apply-update-form');
  const updateLog = document.getElementById('update-modal-log');
  const updatePhase = document.getElementById('update-modal-phase');
  const updateFill = document.getElementById('update-modal-progress');
  const updatePercent = document.getElementById('update-modal-percent');
  const updateState = document.getElementById('update-modal-state');
  const updateSpinner = document.getElementById('update-spinner');
  const closeUpdateModal = document.getElementById('close-update-modal');
  const copyUpdateLog = document.getElementById('copy-update-log');
  let updatePollHandle = null;
  function showUpdateModal() {
    if (!updateModal) return;
    updateModal.hidden = false;
    document.body.style.overflow = 'hidden';
    updatePhase.textContent = 'Starting update…';
    updateLog.value = 'Waiting for server output…';
    updateFill.style.width = '0%';
    updatePercent.textContent = '0%';
    updateState.textContent = 'RUNNING';
    updateSpinner.className = 'update-modal-spinner';
    closeUpdateModal.disabled = true;
    closeUpdateModal.textContent = 'Update running…';
    document.getElementById('update-copy-status').textContent = '';
  }
  function finishUpdateModal(success) {
    closeUpdateModal.disabled = false;
    closeUpdateModal.textContent = 'Close';
    updateState.textContent = success ? 'SUCCESS' : 'FAILED';
    updateSpinner.className = 'update-modal-spinner ' + (success ? 'is-done' : 'is-failed');
    if (!success) updatePhase.textContent = 'Update failed. Copy the output below to share the exact error.';
  }
  async function pollUpdateStatus() {
    try {
      const response = await fetch('/update/status', {headers: {'Accept': 'application/json'}, cache: 'no-store'});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not read updater status.');
      updateLog.value = result.log || '(No output received yet.)';
      updateLog.scrollTop = updateLog.scrollHeight;
      updatePhase.textContent = result.phase || 'Working…';
      const percent = Math.max(0, Math.min(100, Number(result.progress) || 0));
      updateFill.style.width = percent + '%';
      updatePercent.textContent = percent + '%';
      if (result.done) {
        if (updatePollHandle) clearInterval(updatePollHandle);
        updatePollHandle = null;
        if (result.success) {
          updateFill.style.width = '100%'; updatePercent.textContent = '100%';
          updatePhase.textContent = 'Update completed successfully.';
          finishUpdateModal(true);
          const currentLine = document.getElementById('current-version');
          if (currentLine && result.current) currentLine.textContent = result.current;
          const status = document.getElementById('update-status-text');
          if (status) status.textContent = 'Update completed successfully.';
        } else finishUpdateModal(false);
      }
    } catch (error) {
      updateLog.value += '\n' + (error.message || 'Unable to poll updater status.');
      updatePhase.textContent = 'Could not read updater status.';
      if (updatePollHandle) clearInterval(updatePollHandle);
      updatePollHandle = null;
      finishUpdateModal(false);
    }
  }
  applyUpdateForm?.addEventListener('submit', async event => {
    event.preventDefault();
    showUpdateModal();
    try {
      const response = await fetch(applyUpdateForm.action, {
        method: 'POST', body: new FormData(applyUpdateForm),
        headers: {'Accept': 'text/html'}, cache: 'no-store'
      });
      const html = await response.text();
      if (!response.ok || /Update could not start|Updater is not installed|Check for updates first|GitHub changed since the check|No update is available/.test(html)) {
        updateLog.value = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || ('HTTP ' + response.status);
        throw new Error('The updater did not start. Copy the diagnostic output below.');
      }
      updatePollHandle = setInterval(pollUpdateStatus, 1200);
      await pollUpdateStatus();
    } catch (error) {
      if (updatePollHandle) clearInterval(updatePollHandle);
      updatePollHandle = null;
      updateLog.value = (updateLog.value || '') + '\n' + (error.message || String(error));
      finishUpdateModal(false);
    }
  });
  closeUpdateModal?.addEventListener('click', () => {
    if (closeUpdateModal.disabled) return;
    updateModal.hidden = true;
    document.body.style.overflow = '';
    if (updateState.textContent === 'SUCCESS') window.location.reload();
  });
  copyUpdateLog?.addEventListener('click', async () => {
    const content = 'IP Management updater diagnostic\nStatus: ' + updateState.textContent +
      '\nPhase: ' + updatePhase.textContent + '\n\n' + (updateLog.value || '(empty output)');
    try {
      await navigator.clipboard.writeText(content);
      document.getElementById('update-copy-status').textContent = 'Output copied to clipboard.';
    } catch (_) {
      updateLog.focus(); updateLog.select();
      const copied = document.execCommand('copy');
      document.getElementById('update-copy-status').textContent = copied ? 'Output copied to clipboard.' : 'Select and copy the output manually.';
    }
  });
  const ipModal = document.getElementById('ip-modal');
  const openIpModal = document.getElementById('open-ip-modal');
  const closeIpModal = () => ipModal?.close();
  openIpModal?.addEventListener('click', () => { ipModal?.showModal(); document.getElementById('quick-name')?.focus(); });
  document.getElementById('close-ip-modal')?.addEventListener('click', closeIpModal);
  document.getElementById('cancel-ip-modal')?.addEventListener('click', closeIpModal);
  ipModal?.addEventListener('click', event => { if (event.target === ipModal) closeIpModal(); });
  document.getElementById('quick-ip-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = document.getElementById('save-quick-ip');
    const error = document.getElementById('quick-ip-error');
    button.disabled = true; button.textContent = 'Saving…'; error.hidden = true;
    try {
      const response = await fetch('/ips/new', {method:'POST', body:new FormData(form), headers:{'X-Requested-With':'XMLHttpRequest','Accept':'application/json'}});
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || 'Could not save this IP record.');
      closeIpModal(); window.location.reload();
    } catch (err) { error.textContent = err.message || 'Could not save this IP record.'; error.hidden = false; }
    finally { button.disabled = false; button.textContent = 'Save IP address'; }
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