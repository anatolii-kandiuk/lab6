function setupPasswordHelpers() {
  const EYE = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 12s4-7.5 9.5-7.5S21.5 12 21.5 12s-4 7.5-9.5 7.5S2.5 12 2.5 12z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
  const EYE_OFF = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 19.5C7.5 19.5 3.5 12 3.5 12a19.4 19.4 0 0 1 3.11-4.22"></path><path d="M1 1l22 22"></path></svg>';

  document.querySelectorAll('[data-pw-target]').forEach(function (btn) {
    const inputId = btn.getAttribute('data-pw-target');
    const input = document.getElementById(inputId);
    if (!input) return;
    
    // Set button appearance
    btn.style.color = '#000';
    btn.innerHTML = EYE;

    // Link to requirements list
    const reqId = btn.getAttribute('data-pw-reqs');
    const ul = reqId ? document.getElementById(reqId) : null;
    if (ul) ul.classList.add('d-none');

    // Prepare validation checks
    let checks = [];
    if (ul) {
      ul.querySelectorAll('li[data-regex]').forEach(function (li) {
        try {
          checks.push({ li: li, re: new RegExp(li.getAttribute('data-regex')) });
        } catch (e) {
          console.error('Invalid regex in password requirement:', e);
        }
      });
    }

    const validate = function () {
      const v = input.value || '';
      checks.forEach(function (c) {
        if (c.re.test(v)) {
          c.li.classList.remove('text-danger');
          c.li.classList.add('text-success');
        } else {
          c.li.classList.remove('text-success');
          c.li.classList.add('text-danger');
        }
      });
    };

    // Toggle visibility
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = EYE_OFF;
      } else {
        input.type = 'password';
        btn.innerHTML = EYE;
      }
      input.focus();
    });

    // Show/hide requirements on focus/blur
    input.addEventListener('focus', function () {
      if (ul) ul.classList.remove('d-none');
      validate();
    });
    
    input.addEventListener('input', validate);
    
    input.addEventListener('blur', function () {
      setTimeout(function () {
        const active = document.activeElement;
        if (ul && active !== btn && active !== input && !ul.contains(active)) {
          ul.classList.add('d-none');
        }
      }, 150);
    });

    // Hide if user focuses elsewhere
    document.addEventListener('focusin', function (ev) {
      const target = ev.target;
      if (ul && target !== input && target !== btn && !ul.contains(target)) {
        ul.classList.add('d-none');
      }
    });

    // Initial validation
    validate();
  });
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', setupPasswordHelpers);
