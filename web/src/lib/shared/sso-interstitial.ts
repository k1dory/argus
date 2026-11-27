// Экран «Входим в ARGUS…» между IdP и консолью: самостоятельная страница без
// React (отдаётся route-хендлером мгновенно), сама отправляет code/state POST-ом.
// Без JS — кнопка «Продолжить». Цвета — из палитры консоли (тёмная тема).

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function ssoInterstitialHtml({ code, state, nonce }: { code: string; state: string; nonce?: string }): string {
  const n = nonce ? ` nonce="${esc(nonce)}"` : "";
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Входим в ARGUS…</title>
<style>
html,body{height:100%;margin:0;background:#0a0b0d;color:#e6e8eb;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;padding:24px;text-align:center}
.brand{font-weight:600;letter-spacing:.01em}.brand span{color:#8b919c}
.spin{width:34px;height:34px;border-radius:50%;border:3px solid #2a2e37;border-top-color:#82aaff;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation-duration:2.4s}}
h1{font-size:18px;font-weight:500;margin:0}
p{margin:0;color:#8b919c;font-size:14px;max-width:32em}
#slow{visibility:hidden}
button{font:inherit;font-size:14px;color:#0a0b0d;background:#e6e8eb;border:0;border-radius:6px;padding:9px 18px;cursor:pointer}
a{color:#82aaff}
</style></head>
<body><main role="status" aria-live="polite">
<div class="brand">argus<span>/siem</span></div>
<div class="spin" aria-hidden="true"></div>
<h1>Входим в ARGUS…</h1>
<p>Проверяем вход у поставщика учётных записей и открываем консоль.</p>
<p id="slow">Дольше обычного. Если экран не сменится, <a href="/login">вернитесь на страницу входа</a> и попробуйте снова.</p>
<form id="f" method="post" action="/api/auth/oidc/callback">
<input type="hidden" name="code" value="${esc(code)}"><input type="hidden" name="state" value="${esc(state)}">
<noscript><button type="submit">Продолжить</button></noscript>
</form>
</main>
<script${n}>
document.getElementById("f").submit();
setTimeout(function(){document.getElementById("slow").style.visibility="visible"},15000);
</script>
</body></html>`;
}
