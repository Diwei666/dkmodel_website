document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token');
  const loginBtn = document.getElementById('btn-login');
  const registerBtn = document.getElementById('btn-register');

  if (token) {
    fetch('/api/profile', {
      headers: { 'Authorization': 'Bearer ' + token }
    })
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          localStorage.removeItem('token');
        } else {
          loginBtn.textContent = data.email || '用户';
          loginBtn.href = '#';

          registerBtn.textContent = '登出';
          registerBtn.href = '#';
          registerBtn.style.background = 'var(--brand)';
          registerBtn.style.color = '#fff';
          registerBtn.style.padding = '8px 12px';
          registerBtn.style.borderRadius = '8px';
          registerBtn.style.textDecoration = 'none';

          registerBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            location.reload();
          });
        }
      })
      .catch(err => console.error('获取用户信息失败:', err));
  }

  // 平滑滚动功能
  document.querySelectorAll('[data-scroll]').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  });
});