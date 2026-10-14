(() => {
  const root = document.querySelector('.reconfigure-wait');
  if (!root) return;
  const statusUrl = root.dataset.statusUrl;
  const targetUrl = root.dataset.targetUrl;
  const phase = document.getElementById('reconfigure-phase');
  const progress = document.getElementById('reconfigure-progress');
  const error = document.getElementById('reconfigure-error');
  const actions = document.getElementById('reconfigure-actions');
  let failures = 0;

  async function poll() {
    try {
      const response = await fetch(statusUrl, { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('Status temporarily unavailable');
      const status = await response.json();
      failures = 0;
      if (status.state === 'success') {
        phase.textContent = 'Address changed successfully. Opening the new address…';
        progress.classList.add('is-complete');
        window.location.replace(targetUrl);
        return;
      }
      if (status.state === 'error') {
        phase.textContent = 'The address change could not be completed.';
        error.hidden = false;
        error.textContent = status.message || 'The previous server configuration was restored.';
        actions.hidden = false;
        progress.classList.add('is-error');
        return;
      }
      phase.textContent = status.message || 'Updating server configuration…';
      progress.classList.add('is-running');
    } catch (_) {
      failures += 1;
      if (failures >= 20) {
        phase.textContent = 'The new server is restarting. Opening the target address…';
        window.location.replace(targetUrl);
        return;
      }
    }
    window.setTimeout(poll, 1500);
  }
  window.setTimeout(poll, 1200);
})();
