// Small progressive enhancements; every page works without them.
document.addEventListener('DOMContentLoaded', () => {
  // Show/hide a device's edit row.
  document.querySelectorAll('[data-toggle]').forEach(btn => {
    btn.addEventListener('click', () => {
      const row = document.getElementById(btn.dataset.toggle);
      if (row) row.hidden = !row.hidden;
    });
  });

  // Ask before blocking or unblocking.
  document.querySelectorAll('form[data-confirm]').forEach(f => {
    f.addEventListener('submit', e => {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // Remembered auto-refresh toggle (per page).
  const box = document.querySelector('[data-autorefresh]');
  if (box) {
    const key = 'fd-autorefresh:' + location.pathname;
    let on = false;
    try { on = localStorage.getItem(key) === '1'; } catch (_) {}
    box.checked = on;
    let timer = null;
    const arm = () => {
      clearTimeout(timer);
      if (box.checked) timer = setTimeout(() => location.reload(), Number(box.dataset.autorefresh) * 1000);
    };
    box.addEventListener('change', () => {
      try { localStorage.setItem(key, box.checked ? '1' : '0'); } catch (_) {}
      arm();
    });
    // Don't reload while someone is typing in a form.
    document.addEventListener('focusin', e => { if (e.target.matches('input')) clearTimeout(timer); });
    document.addEventListener('focusout', arm);
    arm();
  }

  // Drop ?ok= / ?err= from the address bar so a reload doesn't repeat the message.
  const u = new URL(location.href);
  if (u.searchParams.has('ok') || u.searchParams.has('err')) {
    u.searchParams.delete('ok'); u.searchParams.delete('err');
    history.replaceState(null, '', u.pathname + (u.search || ''));
  }
});
