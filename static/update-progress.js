(() => {
  const phase = document.getElementById('deploy-phase');
  const percent = document.getElementById('deploy-percent');
  const fill = document.getElementById('deploy-progress-fill');
  const progress = document.getElementById('deploy-progress');
  const log = document.getElementById('deploy-log');
  const message = document.getElementById('deploy-message');
  const spinner = document.getElementById('deploy-spinner');
  const live = document.getElementById('terminal-live');
  let finished = false;
  let updateRunning = true;
  const warnLeaving = event => { if (!updateRunning) return; event.preventDefault(); event.returnValue = 'The server update is still running. Leave this page?'; return event.returnValue; };
  window.addEventListener('beforeunload', warnLeaving);
  history.pushState({deployment:true}, '', location.href);
  window.addEventListener('popstate', () => { if (updateRunning) { history.pushState({deployment:true}, '', location.href); message.textContent = 'The update is still running. Please wait here until it finishes.'; } });
  let logOffset = 0;
  async function poll() {
    if (finished) return;
    try {
      const response = await fetch(`/update/status?offset=${logOffset}&t=${Date.now()}`, {cache: 'no-store', headers: {'Accept': 'application/json'}});
      if (!response.ok) throw new Error('The application service is restarting. Reconnecting…');
      const data = await response.json();
      if (data.log_reset) {
        log.textContent = data.log || 'Waiting for server output…';
      } else if (data.log) {
        if (log.textContent === 'Waiting for server output…') log.textContent = '';
        log.textContent += data.log;
      }
      if (Number.isFinite(Number(data.log_offset))) {
        logOffset = Number(data.log_offset);
      }
      if (data.log || data.log_reset) {
        log.scrollTop = log.scrollHeight;
      }
      const value = Math.max(0, Math.min(100, Number(data.progress) || 0));
      percent.textContent = `${value}%`;
      fill.style.width = `${value}%`;
      progress.setAttribute('aria-valuenow', String(value));
      phase.textContent = data.phase || 'Running update…';
      if (data.done && data.success) {
        finished = true; updateRunning = false; window.removeEventListener('beforeunload', warnLeaving);
        percent.textContent = '100%';
        fill.style.width = '100%';
        phase.textContent = 'Update completed successfully';
        message.textContent = 'Returning to the home page…';
        spinner.hidden = true;
        live.textContent = 'DONE';
        live.classList.add('terminal-live-done');
        setTimeout(() => { window.location.assign('/update/finish'); }, 1800);
        return;
      }
      if (data.done && !data.success) {
        finished = true; updateRunning = false; window.removeEventListener('beforeunload', warnLeaving);
        phase.textContent = 'Update failed';
        message.textContent = 'The existing version was restored when possible. Review the output and try again after resolving the error.';
        spinner.hidden = true;
        live.textContent = 'FAILED';
        live.classList.add('terminal-live-failed');
        return;
      }
      setTimeout(poll, 700);
    } catch (error) {
      phase.textContent = error.message || 'Reconnecting to the server…';
      if (message) message.textContent = 'The app may restart during deployment. Waiting for it to come back online…';
      setTimeout(poll, 1500);
    }
  }
  poll();
})();
