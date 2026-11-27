// Регрессия: серверный модуль, импортирующий из файла с "use client" не
// компонент (словарь, константу, функцию), получает клиентскую заглушку, а не
// значение. Так колонка «Вид» в паспорте и на /actors/lookup была пустой:
// ALIAS_KIND_LABELS жил в actor-forms.tsx. Проверка — по исходникам: из
// клиентских модулей серверные файлы берут только компоненты (PascalCase) и типы.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const SRC = path.join(__dirname, "..", "src");

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(e.name)) out.push(p);
  }
  return out;
}

/** Директива "use client" — первая инструкция модуля (комментарии перед ней допустимы). */
const isClientModule = (src: string): boolean => /^\s*(?:(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)\s*)*["']use client["']/.test(src);

function resolveImport(spec: string, from: string): string | null {
  let base: string;
  if (spec.startsWith("@/")) base = path.join(SRC, spec.slice(2));
  else if (spec.startsWith(".")) base = path.resolve(path.dirname(from), spec);
  else return null;
  for (const ext of ["", ".ts", ".tsx", "/index.ts", "/index.tsx"]) {
    const p = base + ext;
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  }
  return null;
}

/** Имена, которые нельзя брать из клиентского модуля на сервере: всё, кроме компонентов. */
const isComponentName = (n: string): boolean => /^[A-Z][A-Za-z0-9]*$/.test(n) && !/^[A-Z0-9_]+$/.test(n);

function clientValueImports(files: string[]): string[] {
  const client = new Set(files.filter((f) => isClientModule(fs.readFileSync(f, "utf8"))));
  const bad: string[] = [];
  for (const f of files) {
    if (client.has(f)) continue; // клиент из клиента может брать что угодно
    const src = fs.readFileSync(f, "utf8");
    for (const m of src.matchAll(/import\s+(type\s+)?\{([^}]*)\}\s+from\s+["']([^"']+)["']/g)) {
      if (m[1]) continue;
      const target = resolveImport(m[3], f);
      if (!target || !client.has(target)) continue;
      const names = m[2].split(",").map((s) => s.trim()).filter((s) => s && !s.startsWith("type ")).map((s) => s.split(/\s+as\s+/)[0]);
      for (const n of names.filter((n) => !isComponentName(n))) bad.push(`${path.relative(SRC, f)}: ${n} из ${path.relative(SRC, target)}`);
    }
    for (const m of src.matchAll(/import\s+\*\s+as\s+\w+\s+from\s+["']([^"']+)["']/g)) {
      const target = resolveImport(m[1], f);
      if (target && client.has(target)) bad.push(`${path.relative(SRC, f)}: import * из ${path.relative(SRC, target)}`);
    }
  }
  return bad;
}

test("серверные модули не берут из \"use client\" ничего, кроме компонентов и типов", () => {
  assert.deepEqual(clientValueImports(walk(SRC)), []);
});

test("проверка ловит словарь из клиентского модуля (как ALIAS_KIND_LABELS из actor-forms)", () => {
  const dir = fs.mkdtempSync(path.join(SRC, "..", ".tmp-client-boundary-"));
  try {
    const client = path.join(dir, "form.tsx");
    const server = path.join(dir, "page.tsx");
    fs.writeFileSync(client, '"use client";\nexport const LABELS = { a: "b" };\nexport function Form() { return null; }\n');
    fs.writeFileSync(server, 'import { Form, LABELS, type X } from "./form";\n');
    const bad = clientValueImports([client, server]);
    assert.equal(bad.length, 1);
    assert.match(bad[0], /LABELS/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("подписи видов алиасов — в lib/shared, по-русски", async () => {
  const { ALIAS_KIND_LABELS, ALIAS_KINDS } = await import("../src/lib/shared/actors");
  for (const k of ALIAS_KINDS) assert.ok(ALIAS_KIND_LABELS[k], `нет подписи для ${k}`);
  assert.equal(ALIAS_KIND_LABELS.email, "почта");
});

test("ServiceUnavailableView: клиентский импорт не достигает server-only", () => {
  const seen = new Set<string>();
  function visit(file: string, chain: string[] = []): void {
    if (seen.has(file)) return;
    seen.add(file);
    const source = ts.createSourceFile(
      file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true,
    );
    const first = source.statements[0];
    // Импорт server action из клиента допустим.
    if (first && ts.isExpressionStatement(first) &&
        ts.isStringLiteral(first.expression) && first.expression.text === "use server") return;
    for (const node of source.statements) {
      if (!ts.isImportDeclaration(node) && !ts.isExportDeclaration(node)) continue;
      if (ts.isImportDeclaration(node) && node.importClause?.isTypeOnly) continue;
      if (ts.isExportDeclaration(node) && node.isTypeOnly) continue;
      const spec = node.moduleSpecifier;
      if (!spec || !ts.isStringLiteral(spec)) continue;
      const trace = [...chain, path.relative(SRC, file), spec.text];
      assert.notEqual(spec.text, "server-only", trace.join(" -> "));
      const target = resolveImport(spec.text, file);
      if (target) visit(target, [...chain, path.relative(SRC, file)]);
    }
  }
  visit(path.join(SRC, "components/console/service-unavailable-view.tsx"));
});
