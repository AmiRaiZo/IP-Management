(() => {
  const sidebar = document.querySelector('.sidebar');
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebarPreferenceKey = 'ip-management-sidebar-collapsed';
  const mobileSidebarQuery = window.matchMedia('(max-width: 720px)');
  function setSidebarToggleState(expanded) {
    if (!sidebarToggle) return;
    sidebarToggle.setAttribute('aria-expanded', String(expanded));
    sidebarToggle.setAttribute('title', expanded ? 'Hide sidebar' : 'Show sidebar');
    sidebarToggle.setAttribute('aria-label', expanded ? 'Hide sidebar' : 'Show sidebar');
    const label = sidebarToggle.querySelector('.sidebar-toggle-label');
    if (label) label.textContent = expanded ? 'Hide sidebar' : 'Show sidebar';
  }
  function setSidebarCollapsed(collapsed, persist = true) {
    if (!sidebar || !sidebarToggle) return;
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    setSidebarToggleState(!collapsed);
    if (persist) {
      try { localStorage.setItem(sidebarPreferenceKey, collapsed ? '1' : '0'); } catch (_) {}
    }
  }
  function applySidebarMode() {
    if (!sidebar || !sidebarToggle) return;
    document.body.classList.remove('mobile-sidebar-open');
    if (mobileSidebarQuery.matches) {
      // Phones always start with the drawer closed, independent of desktop preference.
      document.body.classList.remove('sidebar-collapsed');
      setSidebarToggleState(false);
      return;
    }
    let collapsed = false;
    try { collapsed = localStorage.getItem(sidebarPreferenceKey) === '1'; } catch (_) {}
    setSidebarCollapsed(collapsed, false);
  }
  if (sidebar && sidebarToggle) {
    applySidebarMode();
    if (typeof mobileSidebarQuery.addEventListener === 'function') {
      mobileSidebarQuery.addEventListener('change', applySidebarMode);
    } else {
      mobileSidebarQuery.addListener(applySidebarMode);
    }
    sidebarToggle.addEventListener('click', () => {
      if (mobileSidebarQuery.matches) {
        const expanded = document.body.classList.toggle('mobile-sidebar-open');
        setSidebarToggleState(expanded);
      } else {
        setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed'));
      }
    });
    function closeMobileSidebar() {
      if (!mobileSidebarQuery.matches || !document.body.classList.contains('mobile-sidebar-open')) return;
      document.body.classList.remove('mobile-sidebar-open');
      setSidebarToggleState(false);
    }
    document.addEventListener('click', event => {
      if (!document.body.classList.contains('mobile-sidebar-open')) return;
      if (sidebar.contains(event.target) || sidebarToggle.contains(event.target)) return;
      closeMobileSidebar();
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') closeMobileSidebar();
    });
  }
  document.querySelectorAll('[data-auto-dismiss]').forEach(toast => {
    let dismissed = false;
    const dismissOnClick = () => dismiss();
    const dismiss = () => {
      if (dismissed) return;
      dismissed = true;
      document.removeEventListener('click', dismissOnClick, true);
      toast.classList.add('toast-leaving');
      window.setTimeout(() => toast.remove(), 220);
    };
    if (toast.classList.contains('welcome-toast')) {
      document.addEventListener('click', dismissOnClick, true);
    }
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
  const updateSuccessModal = document.getElementById('update-success-modal');
  const closeUpdateSuccess = () => {
    if (!updateSuccessModal) return;
    updateSuccessModal.remove();
    const url = new URL(window.location.href);
    url.searchParams.delete('update');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  };
  document.getElementById('close-update-success')?.addEventListener('click', closeUpdateSuccess);
  updateSuccessModal?.addEventListener('click', event => {
    if (event.target === updateSuccessModal) closeUpdateSuccess();
  });
  if (updateSuccessModal) document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeUpdateSuccess();
  });
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
  const copyUpdateLog = document.getElementById('copy-update-log');
  const closeUpdateModal = document.getElementById('close-update-modal');
  let updatePollHandle = null;
  let updatePollFailures = 0;
  function showUpdateModal() {
    if (!updateModal) return;
    updateModal.hidden = false;
    document.body.style.overflow = 'hidden';
    updatePhase.textContent = 'Starting update…';
    updateLog.value = 'Waiting for server output…';
    updateFill.style.width = '0%';
    updatePercent.textContent = '0%';
    updateState.textContent = 'RUNNING';
    if (closeUpdateModal) closeUpdateModal.hidden = true;
    document.documentElement.classList.add('updater-modal-open');
    document.getElementById('update-copy-status').textContent = '';
  }
  function finishUpdateModal(success) {
    updateState.textContent = success ? 'SUCCESS' : 'FAILED';
    if (!success) {
      updatePhase.textContent = 'Update failed';
      if (closeUpdateModal) closeUpdateModal.hidden = false;
    }
    if (success) window.setTimeout(() => window.location.assign('/update/finish'), 1200);
  }
  closeUpdateModal?.addEventListener('click', () => {
    if (updateState.textContent !== 'FAILED') return;
    updateModal.hidden = true;
    document.body.style.overflow = '';
    document.documentElement.classList.remove('updater-modal-open');
  });
  document.addEventListener('keydown', event => {
    if (updateModal && !updateModal.hidden && event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
    }
  }, true);
  async function pollUpdateStatus() {
    try {
      const response = await fetch('/update/status', {headers: {'Accept': 'application/json'}, cache: 'no-store'});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not read updater status.');
      updatePollFailures = 0;
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
      // The app service is stopped briefly during deployment. Keep polling while
      // it restarts instead of treating a temporary 502/network error as failure.
      updatePollFailures += 1;
      updatePhase.textContent = 'Reconnecting…';
      updateState.textContent = 'RUNNING';
      if (updatePollFailures >= 600) {
        if (updatePollHandle) clearInterval(updatePollHandle);
        updatePollHandle = null;
        updateLog.value += '\nUpdate status could not be reached for 12 minutes.';
        finishUpdateModal(false);
      }
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
        throw new Error('Could not start update.');
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
  copyUpdateLog?.addEventListener('click', async () => {
    const content = updateLog.value || '(empty output)';
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
  const mobileRows = [...document.querySelectorAll('[data-mobile-search-row]')];
  function filterRows() {
    const query = (search?.value || '').trim().toLowerCase();
    const groupName = group?.value || '';
    let count = 0;
    rows.forEach(row => {
      const visible = (!query || (row.dataset.search || '').toLowerCase().includes(query)) && (!groupName || row.dataset.group === groupName);
      row.hidden = !visible;
      if (visible) count++;
    });
    mobileRows.forEach(row => {
      const visible = (!query || (row.dataset.search || '').toLowerCase().includes(query)) && (!groupName || row.dataset.group === groupName);
      row.hidden = !visible;
    });
    const counter = document.querySelector('[data-visible-count]');
    if (counter) counter.textContent = String(count);
    const empty = document.querySelector('[data-filter-empty]');
    if (empty) empty.hidden = count !== 0;
  }
  search?.addEventListener('input', filterRows);
  group?.addEventListener('change', filterRows);
  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      const field = document.createElement('textarea');
      field.value = value;
      field.setAttribute('readonly', '');
      field.style.position = 'fixed'; field.style.opacity = '0';
      document.body.appendChild(field); field.select();
      const copied = document.execCommand('copy'); field.remove();
      return copied;
    }
  }
  // Delegate copy handling so dynamically populated mobile modal fields also work.
  document.addEventListener('click', async event => {
    const button = event.target instanceof Element ? event.target.closest('[data-copy-value]') : null;
    if (!button) return;
    const value = button.dataset.copyValue || '';
    if (!value) return;
    const originalTitle = button.dataset.originalTitle || button.title || 'Click to copy value';
    button.dataset.originalTitle = originalTitle;
    if (await copyText(value)) {
      button.classList.add('is-copied');
      button.title = 'Copied!';
      button.setAttribute('aria-label', 'Copied');
      window.setTimeout(() => {
        button.classList.remove('is-copied');
        button.title = originalTitle;
        button.setAttribute('aria-label', originalTitle.replace(/^Click to copy /, 'Copy '));
      }, 1200);
    }
  });

  const mobileIpDetailsModal = document.getElementById('mobile-ip-details-modal');
  const mobileIpDetailsTitle = document.getElementById('mobile-ip-details-title');
  const mobileIpDetailsList = document.getElementById('mobile-ip-details-list');

  function addMobileIpDetail(label, value, copyable = false) {
    if (!mobileIpDetailsList) return;
    const row = document.createElement('div');
    row.className = 'mobile-ip-detail-row';
    const labelElement = document.createElement('span');
    labelElement.className = 'mobile-ip-detail-label';
    labelElement.textContent = label;
    row.appendChild(labelElement);

    const normalized = String(value || '');
    if (copyable && normalized) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'copy-value mobile-ip-copy';
      button.dataset.copyValue = normalized;
      button.title = 'Click to copy ' + label;
      button.setAttribute('aria-label', 'Copy ' + label);
      const code = document.createElement('code');
      code.textContent = normalized;
      button.appendChild(code);
      row.appendChild(button);
    } else {
      const valueElement = document.createElement('span');
      valueElement.className = 'mobile-ip-detail-value';
      valueElement.textContent = normalized || '—';
      row.appendChild(valueElement);
    }
    mobileIpDetailsList.appendChild(row);
  }

  document.querySelectorAll('[data-mobile-ip-card]').forEach(card => {
    card.addEventListener('click', () => {
      if (!mobileIpDetailsModal || !mobileIpDetailsList) return;
      const data = card.dataset;
      mobileIpDetailsTitle.textContent = data.ipName || data.ipAddress || 'IP details';
      mobileIpDetailsList.replaceChildren();
      addMobileIpDetail('Group', data.ipGroup, false);
      addMobileIpDetail('IP address', data.ipAddress, true);
      addMobileIpDetail('Port', data.ipPort, true);
      addMobileIpDetail('Username', data.ipUsername, true);
      if (card.hasAttribute('data-ip-password')) addMobileIpDetail('Password', data.ipPassword, true);
      if (data.ipNotes) addMobileIpDetail('Notes', data.ipNotes, false);
      if (!mobileIpDetailsModal.open) mobileIpDetailsModal.showModal();
    });
  });
  document.getElementById('close-mobile-ip-details')?.addEventListener('click', () => mobileIpDetailsModal?.close());
  mobileIpDetailsModal?.addEventListener('click', event => {
    if (event.target === mobileIpDetailsModal) mobileIpDetailsModal.close();
  });

  document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    try { await navigator.clipboard.writeText(target.value || target.textContent || ''); button.textContent = 'Copied'; }
    catch (_) { target.focus(); target.select?.(); }
  }));
})();
