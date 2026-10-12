// Theme (light/dark) toggle — saved in browser
(function () {
  var root = document.documentElement;
  function get() { try { return localStorage.getItem('maswer-theme'); } catch (e) { return null; } }
  function set(v) { try { localStorage.setItem('maswer-theme', v); } catch (e) {} }
  function current() {
    var t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  var saved = get();
  if (saved) root.setAttribute('data-theme', saved);
  document.addEventListener('DOMContentLoaded', function () {
    var b = document.createElement('button');
    b.className = 'theme-fab';
    b.title = 'Light / Dark theme';
    function paint() { b.textContent = current() === 'dark' ? '☀️' : '🌙'; }
    b.onclick = function () {
      var n = current() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', n); set(n); paint();
    };
    paint();
    document.body.appendChild(b);
  });
})();
