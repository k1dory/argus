/* eslint-disable @typescript-eslint/no-require-imports -- моки Next ставятся до загрузки auth/actions/страниц */
// Регрессии страницы входа:
// - после неверного пароля логин не стирается (React 19 сбрасывает форму
//   после action — значение должно вернуться из state и стать defaultValue);
// - подсказка про стартовый пароль admin — только пока он не сменён;
// - ошибки SSO различаются: «группа не даёт доступа» отдельно от отказа IdP.
import { before, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { formData, installNextMocks, loadAuth, type AuthModule } from "./_next-mock";
import { html, pageText, stripTags } from "./_render";

const mocks = installNextMocks();
let auth: AuthModule;
let actions: typeof import("../src/lib/actions");
const React = require("react") as typeof import("react");
const loginForm = require("../src/components/console/login-form") as typeof import("../src/components/console/login-form");
const { ssoErrorText } = require("../src/lib/shared/login") as typeof import("../src/lib/shared/login");
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string | string[] | undefined>> };
const login = require("../src/app/login/page") as { default: (p: Props) => Promise<unknown> };
const props = (sp: Record<string, string> = {}): Props => ({ params: Promise.resolve({}), searchParams: Promise.resolve(sp) });

before(async () => {
  auth = loadAuth();
  actions = require("../src/lib/actions") as typeof import("../src/lib/actions");
  assert.ok("password" in (await auth.createUser("analyst1", "analyst")));
});

test("неверный пароль: action возвращает введённый логин (нормализованный), форма показывает его снова", async () => {
  mocks.jar.clear();
  const res = await actions.loginAction({ error: null }, formData({ user: " Analyst1 ", password: "wrong" }));
  assert.match(res.error ?? "", /Неверный логин или пароль/);
  assert.equal(res.user, "analyst1");

  const out = html(React.createElement(loginForm.LoginFields, { state: res }));
  assert.match(out, /<input[^>]*id="user"[^>]*value="analyst1"/, "логин остаётся в поле после ошибки");
  assert.match(out, /role="alert"/);
  // Фокус — на пароле: логин уже введён, его не надо набирать заново.
  assert.doesNotMatch(out, /<input[^>]*id="user"[^>]*autofocus/i);

  const fresh = html(React.createElement(loginForm.LoginFields, { state: { error: null } }));
  assert.match(fresh, /<input[^>]*id="user"[^>]*value=""/);
  assert.doesNotMatch(fresh, /role="alert"/);
});

test("ошибки SSO: группа без доступа, отказ IdP и устаревший сеанс — разные тексты", () => {
  const noRole = ssoErrorText("no_role", null);
  const denied = ssoErrorText("denied", null);
  const state = ssoErrorText("state", "https://argus.example:8443");
  assert.match(noRole, /группа не даёт доступа/);
  assert.match(noRole, /администратор/);
  assert.doesNotMatch(denied, /групп/);
  assert.match(state, /https:\/\/argus\.example:8443/);
  assert.notEqual(noRole, denied);
});

test("страница входа: один заголовок; подсказка про стартовый пароль — только до его смены; SSO — первой кнопкой", async () => {
  mocks.jar.clear();
  delete process.env.OIDC_ISSUER;
  let text = await pageText(await login.default(props()));
  assert.match(text, /Вход в ARGUS/);
  assert.doesNotMatch(text, /в одном месте/, "без рекламного слогана");
  assert.match(text, /стартовый пароль admin/, "первый запуск — подсказка видна");

  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  text = await pageText(await login.default(props()));
  assert.doesNotMatch(text, /стартовый пароль|auth\.json/, "после смены пароля — ни слова о файле с паролем");
  assert.match(text, /Обратитесь к администратору ARGUS/);

  process.env.OIDC_ISSUER = "https://idp.example/application/o/argus/";
  process.env.OIDC_CLIENT_ID = "argus";
  process.env.OIDC_REDIRECT_URL = "https://argus.example:8443/api/auth/oidc/callback";
  try {
    text = await pageText(await login.default(props({ sso: "no_role" })));
    assert.ok(text.indexOf("Войти через корпоративную учётную запись") < text.indexOf("Войти по паролю ARGUS"), "SSO — первым");
    assert.match(stripTags(text), /группа не даёт доступа к ARGUS/);
  } finally {
    delete process.env.OIDC_ISSUER;
  }
});
