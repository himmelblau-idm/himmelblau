(() => {
  const rows = [...document.querySelectorAll('.file-row')];
  const pane = document.getElementById('details-pane');
  const openButton = document.getElementById('open-selected');
  const status = document.getElementById('selection-status');
  if (!pane || !openButton || !status) return;

  let selected = null;
  let request = null;

  function openSelected() {
    if (selected) window.location.assign(selected.dataset.open);
  }

  async function select(row) {
    if (selected) {
      selected.classList.remove('selected');
      selected.setAttribute('aria-selected', 'false');
    }
    selected = row;
    row.classList.add('selected');
    row.setAttribute('aria-selected', 'true');
    openButton.disabled = false;
    status.textContent = `${row.dataset.name} selected`;
    pane.classList.add('is-open');
    pane.querySelector('.detail-content, .details-empty, .detail-error, .detail-loading')?.remove();
    pane.insertAdjacentHTML('beforeend', '<p class="detail-loading" role="status">Loading details…</p>');

    if (request) request.abort();
    request = new AbortController();
    const current = request;
    try {
      const url = new URL(row.dataset.details, window.location.href);
      url.searchParams.set('panel', '1');
      const response = await fetch(url, { signal: current.signal, credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const markup = await response.text();
      if (request !== current) return;
      pane.querySelector('.detail-loading')?.remove();
      pane.insertAdjacentHTML('beforeend', markup);
    } catch (error) {
      if (error.name === 'AbortError' || request !== current) return;
      pane.querySelector('.detail-loading')?.remove();
      pane.insertAdjacentHTML('beforeend', '<p class="detail-error" role="alert">File details are unavailable. You can still open the selected file.</p>');
    }
  }

  rows.forEach((row, index) => {
    if (row.classList.contains('selectable')) {
      row.addEventListener('click', (event) => {
        event.preventDefault();
        select(row);
      });
      row.addEventListener('dblclick', (event) => {
        event.preventDefault();
        window.location.assign(row.dataset.open);
      });
    }
    row.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const next = rows[Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)))];
        next.focus();
        if (next.classList.contains('selectable')) select(next);
      } else if (event.key === 'Enter' && row.classList.contains('selectable')) {
        event.preventDefault();
        window.location.assign(row.dataset.open);
      } else if (event.key === ' ' && row.classList.contains('selectable')) {
        event.preventDefault();
        select(row);
      }
    });
  });

  openButton.addEventListener('click', openSelected);
  document.getElementById('close-details')?.addEventListener('click', () => pane.classList.remove('is-open'));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && pane.classList.contains('is-open')) {
      pane.classList.remove('is-open');
      selected?.focus();
    }
  });
})();
