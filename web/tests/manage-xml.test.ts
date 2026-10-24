import { test } from "node:test";
import assert from "node:assert/strict";
import { checkXmlRoots, formatXmlError, validateXml, wrapXmlRoots, xmlRootNames } from "../src/lib/shared/xml";
import { GROUP_NAME_RE, RULE_FILE_RE } from "../src/lib/shared/wazuh-names";

const AGENT_CONF = `<agent_config>
  <!-- Конфигурация группы; разъедется на агентов при следующем keepalive -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <syscheck>
    <directories check_all="yes" realtime='yes'>/etc,/usr/bin</directories>
    <ignore type="sregex">.log$|.swp$</ignore>
  </syscheck>
  <client_buffer><disabled>no</disabled></client_buffer>
  <empty/>
</agent_config>
`;

const RULES = `<?xml version="1.0"?>
<group name="local,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <match>^Failed password</match>
    <regex>a|b</regex>
    <description>Пример: переопределение уровня для sshd &lt;x&gt;</description>
    <group>authentication_failed,</group>
  </rule>
  <rule id="100002" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <description><![CDATA[Брутфорс <sshd>]]></description>
  </rule>
</group>
`;

test("валидный agent.conf и файл правил проходят", () => {
  assert.equal(validateXml(AGENT_CONF), null);
  assert.equal(validateXml(RULES), null);
});

test("незакрытый тег — ошибка с номером строки открытия", () => {
  const e = validateXml(`<agent_config>\n  <localfile>\n    <location>/x</location>\n</agent_config>\n`);
  assert.ok(e);
  assert.equal(e.line, 4);
  assert.match(e.message, /ожидался <\/localfile>/);
  assert.match(e.message, /строке 2/);
  assert.equal(formatXmlError(e), `строка 4: ${e.message}`);

  const tail = validateXml(`<group name="a,">\n  <rule id="1" level="1">\n  <description>x</description>\n`);
  assert.ok(tail);
  assert.match(tail.message, /незакрытый тег <rule>/);
  assert.equal(tail.line, 2);
});

test("битый синтаксис: лишний закрывающий, кривые атрибуты, незакрытый комментарий, текст вне элементов", () => {
  assert.match(validateXml(`<a></a></b>`)?.message ?? "", /без открывающего/);
  assert.match(validateXml(`<a x=1></a>`)?.message ?? "", /атрибут/);
  assert.match(validateXml(`<a x="1></a>`)?.message ?? "", /атрибут|не закрыт/);
  assert.match(validateXml(`<a><!-- x </a>`)?.message ?? "", /комментарий/);
  assert.match(validateXml(`<a><b></a>`)?.message ?? "", /ожидался <\/b>/);
  assert.match(validateXml(`<a><b</a>`)?.message ?? "", /«<» внутри тега/);
  assert.match(validateXml(`hello <a/>`)?.message ?? "", /текст вне элементов/);
  assert.match(validateXml(`<a/> tail`)?.message ?? "", /текст вне элементов/);
  assert.match(validateXml(`<a>\n<b>`)?.message ?? "", /незакрытый тег <b>/);
  assert.match(validateXml(`<a`)?.message ?? "", /нет «>»/);
  assert.match(validateXml(``)?.message ?? "", /нет ни одного элемента/);
  assert.match(validateXml(`<![CDATA[ x`)?.message ?? "", /CDATA/);
});

test("несколько корневых элементов — норма Wazuh: agent.conf с двумя <agent_config>, правила с двумя <group>", () => {
  const conf = `<agent_config os="Linux">\n  <localfile><location>/var/log/syslog</location></localfile>\n</agent_config>\n<!-- профиль -->\n<agent_config profile="web">\n  <syscheck><directories>/var/www</directories></syscheck>\n</agent_config>\n`;
  assert.equal(validateXml(conf), null);
  assert.deepEqual(xmlRootNames(conf), ["agent_config", "agent_config"]);
  assert.equal(checkXmlRoots(conf, "agent_config"), null);
  const rules = `<?xml version="1.0"?>\n<group name="a,"><rule id="1" level="1"><description>x</description></rule></group>\n<group name="b,"><rule id="2" level="1"><description>y</description></rule></group>\n`;
  assert.equal(validateXml(rules), null);
  assert.deepEqual(xmlRootNames(rules), ["group", "group"]);
  assert.equal(checkXmlRoots(rules, "group"), null);
  assert.match(checkXmlRoots(`<agent_config/><foo/>`, "agent_config") ?? "", /ожидается agent_config, встречен корневой <foo>/);
  assert.match(checkXmlRoots(`<foo><group/></foo>`, "group") ?? "", /ожидается group/);
  // Комментарий и декларация между корнями — не «текст вне элементов»
  assert.equal(validateXml(`<!-- a -->\n<a/>\n<!-- b -->\n<b/>\n`), null);
});

test("«>» внутри значения атрибута не закрывает тег; «<» в значении — ошибка", () => {
  assert.equal(validateXml(`<a x="1 > 0"></a>`), null);
  assert.equal(validateXml(`<a x='1 > 0' y="a>b"><c z=">"></c></a>`), null);
  assert.equal(validateXml(`<a x='say "hi" > ok'/>`), null);
  assert.equal(validateXml(`<group name="a,"><rule id="1" level="1"><field name="x" negate="no" type="pcre2">^</field></rule></group>`), null);
  assert.match(validateXml(`<a x="1 < 0"></a>`)?.message ?? "", /«<» внутри тега/);
  assert.match(validateXml(`<a x="1 > 0"`)?.message ?? "", /нет «>»/);
});

test("wrapXmlRoots: синтетический корень для DOMParser, декларация снимается, строки не сдвигаются", () => {
  assert.equal(wrapXmlRoots(`<a/><b/>`), `<argus-root><a/><b/></argus-root>`);
  const src = `<?xml version="1.0" encoding="UTF-8"?>\n<group name="a,"/>\n<group name="b,"/>`;
  const wrapped = wrapXmlRoots(src);
  assert.equal(wrapped, `<argus-root>\n<group name="a,"/>\n<group name="b,"/></argus-root>`);
  assert.equal(wrapped.split("\n").length, src.split("\n").length, "номера строк совпадают");
  assert.equal(validateXml(wrapped), null);
  assert.deepEqual(xmlRootNames(wrapped), ["argus-root"]);
});

test("имена групп и файлов правил: одна регулярка для GET-страницы и для сохранения", () => {
  assert.ok(GROUP_NAME_RE.test("web-servers_01.prod"));
  assert.ok(!GROUP_NAME_RE.test("../default"));
  assert.ok(!GROUP_NAME_RE.test(".hidden"));
  assert.ok(!GROUP_NAME_RE.test("a b"));
  assert.ok(!GROUP_NAME_RE.test(""));
  assert.ok(RULE_FILE_RE.test("local_rules_custom.xml"));
  assert.ok(!RULE_FILE_RE.test("../../etc/ossec.conf"));
  assert.ok(!RULE_FILE_RE.test("rules.txt"));
  assert.ok(!RULE_FILE_RE.test(".xml"));
  assert.ok(!RULE_FILE_RE.test("a/b.xml"));
});
