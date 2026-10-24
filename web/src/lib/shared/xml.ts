// Проверка well-formed XML для agent.conf и файлов правил Wazuh без
// зависимостей: стековый разбор тегов. Ловит незакрытые/лишние теги,
// перепутанную вложенность, битые открывающие теги и незакрытые
// комментарии/CDATA. Это не полный парсер — схему Wazuh проверяет сам
// менеджер (/manager/configuration/validation), здесь отсекается синтаксис.
// Несколько корневых элементов — норма: Wazuh штатно держит несколько
// <agent_config> в agent.conf и несколько <group> в файле правил, поэтому
// «второй корень» ошибкой не считается — какие корни допустимы, решает
// вызывающий (checkXmlRoots). Работает и на сервере, и в браузере (там
// дублируется DOMParser'ом).

export type XmlError = { line: number; message: string };

const NAME_RE = /^[A-Za-z_:][\w.:-]*/;

function lineAt(src: string, pos: number): number {
  let line = 1;
  for (let i = 0; i < pos && i < src.length; i++) if (src.charCodeAt(i) === 10) line++;
  return line;
}

/** Разбор атрибутов открывающего тега: name="v" / name='v'; возвращает ошибку или null. */
function checkAttrs(attrs: string): string | null {
  const re = /\s+([A-Za-z_:][\w.:-]*)\s*=\s*("[^"]*"|'[^']*')/y;
  let i = 0;
  while (i < attrs.length) {
    const rest = attrs.slice(i);
    if (/^\s*$/.test(rest)) return null;
    re.lastIndex = 0;
    const m = re.exec(rest);
    if (!m) return `некорректный атрибут: «${rest.trim().slice(0, 30)}»`;
    i += m[0].length;
  }
  return null;
}

/** Конец тега «>» с учётом кавычек: в `<a x="1 > 0">` «>» внутри значения тег не закрывает.
 *  Возвращает позицию «>», -1 (не найден) или -2 (встречен «<» — предыдущий тег не закрыт). */
function tagEnd(src: string, from: number): number {
  let quote: string | null = null;
  for (let i = from; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "<") return -2; // сырой «<» в значении атрибута XML запрещён
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === ">") return i;
    else if (c === "<") return -2;
  }
  return -1;
}

type Scan = { error: XmlError | null; roots: string[] };

function scan(src: string): Scan {
  const stack: { name: string; line: number }[] = [];
  const roots: string[] = [];
  let i = 0;
  const n = src.length;
  const fail = (pos: number, message: string): Scan => ({ error: { line: lineAt(src, pos), message }, roots });
  while (i < n) {
    const lt = src.indexOf("<", i);
    if (lt === -1) {
      if (stack.length === 0 && src.slice(i).trim() !== "") return fail(i, "текст вне элементов");
      break;
    }
    // Текст вне элементов допустим только как пробелы (комментарии/декларации обрабатываются ниже)
    if (lt > i && stack.length === 0 && src.slice(i, lt).trim() !== "") return fail(i, "текст вне элементов");
    if (src.startsWith("<!--", lt)) {
      const end = src.indexOf("-->", lt + 4);
      if (end === -1) return fail(lt, "незакрытый комментарий");
      i = end + 3;
      continue;
    }
    if (src.startsWith("<![CDATA[", lt)) {
      const end = src.indexOf("]]>", lt + 9);
      if (end === -1) return fail(lt, "незакрытая секция CDATA");
      i = end + 3;
      continue;
    }
    if (src.startsWith("<?", lt)) {
      const end = src.indexOf("?>", lt + 2);
      if (end === -1) return fail(lt, "незакрытая инструкция <? … ?>");
      i = end + 2;
      continue;
    }
    if (src.startsWith("<!", lt)) {
      const end = src.indexOf(">", lt + 2);
      if (end === -1) return fail(lt, "незакрытая декларация <! … >");
      i = end + 1;
      continue;
    }
    const gt = tagEnd(src, lt + 1);
    if (gt === -1) return fail(lt, "незакрытый тег: нет «>»");
    if (gt === -2) return fail(lt, "«<» внутри тега — вероятно, не закрыт предыдущий");
    const inner = src.slice(lt + 1, gt);
    if (inner.startsWith("/")) {
      const name = inner.slice(1).trim();
      if (!NAME_RE.test(name) || NAME_RE.exec(name)![0] !== name) {
        return fail(lt, `некорректный закрывающий тег </${name.slice(0, 30)}>`);
      }
      const top = stack.pop();
      if (!top) return fail(lt, `закрывающий тег </${name}> без открывающего`);
      if (top.name !== name) return fail(lt, `ожидался </${top.name}> (открыт на строке ${top.line}), встречен </${name}>`);
      i = gt + 1;
      continue;
    }
    const selfClosing = inner.endsWith("/");
    const body = selfClosing ? inner.slice(0, -1) : inner;
    const nm = NAME_RE.exec(body);
    if (!nm) return fail(lt, `некорректное имя тега: «${body.trim().slice(0, 30)}»`);
    const attrErr = checkAttrs(body.slice(nm[0].length));
    if (attrErr) return fail(lt, `<${nm[0]}>: ${attrErr}`);
    if (stack.length === 0) roots.push(nm[0]);
    if (!selfClosing) stack.push({ name: nm[0], line: lineAt(src, lt) });
    i = gt + 1;
  }
  if (stack.length > 0) {
    const top = stack[stack.length - 1];
    return { error: { line: top.line, message: `незакрытый тег <${top.name}>` }, roots };
  }
  if (roots.length === 0) return { error: { line: 1, message: "нет ни одного элемента" }, roots };
  return { error: null, roots };
}

export function validateXml(src: string): XmlError | null {
  return scan(src).error;
}

/** Имена корневых элементов по порядку (для well-formed документа; иначе — что успело разобраться). */
export function xmlRootNames(src: string): string[] {
  return scan(src).roots;
}

/** Все корневые элементы должны называться `expected`; ошибка — первое отклонение. */
export function checkXmlRoots(src: string, expected: string): string | null {
  const other = xmlRootNames(src).find((r) => r !== expected);
  return other === undefined ? null : `ожидается ${expected}, встречен корневой <${other}>`;
}

/** Обёртка для DOMParser в браузере: он не принимает несколько корней, а Wazuh
 *  их допускает. Декларация <?xml …?> обязана стоять первой — снимаем её
 *  (без переноса строки, чтобы номера строк в ошибках не сдвигались). */
export const XML_WRAP_ROOT = "argus-root";
export function wrapXmlRoots(src: string): string {
  return `<${XML_WRAP_ROOT}>${src.replace(/^(\s*)<\?xml[^>]*\?>/, "$1")}</${XML_WRAP_ROOT}>`;
}

export const formatXmlError = (e: XmlError): string => `строка ${e.line}: ${e.message}`;
