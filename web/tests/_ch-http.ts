// Транспорт ClickHouse 24.8 для тестов. Без wait_end_of_query сервер дописывает позднее
// исключение в конец тела со статусом 200; с wait_end_of_query=1 отвечает HTTP-ошибкой с
// X-ClickHouse-Exception-Code (проверено на живом 24.8). Исключением считаются только
// формы, которые пишет сам сервер: отдельная строка «Code: N. DB::Exception…»,
// «Poco::Exception. Code: N,», «std::exception. Code: N,» и JSONEachRow-хвост
// {"exception": "…"} — с пробелом после двоеточия (JSONUtils::writeException). Строка
// данных {"exception":"Code: 1."} (колонка с таким именем) — данные.
const EXCEPTION_LINE = /^(?:\{"exception": ")?(?:Poco::Exception\. |std::exception\. )?Code: (\d+)[.,][^\n]*$/m;

// HTTP-статус по коду исключения в 24.8 (exceptionCodeToHTTPStatus, HTTPHandler.cpp);
// коды без особой ветки (в том числе ACCESS_DENIED 497) — 500.
const STATUS: Record<number, number> = {
  6: 400, 25: 400, 27: 400, 36: 400, 53: 400, 62: 400,
  46: 404, 47: 404, 60: 404, 81: 404, 115: 404,
  192: 403, 193: 403, 512: 403, 516: 403,
  194: 401, 48: 501, 76: 503, 209: 503, 439: 503,
  159: 408, 229: 413, 381: 411,
};

export function chHttp(body: string, init: ResponseInit = {}) {
  return async (input: URL | string | Request): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const m = EXCEPTION_LINE.exec(body);
    if (url.searchParams.get("wait_end_of_query") === "1" && m && (init.status ?? 200) === 200) {
      const code = Number(m[1]);
      const headers = new Headers(init.headers);
      headers.set("X-ClickHouse-Exception-Code", String(code));
      return new Response(m[0] + "\n", { status: STATUS[code] ?? 500, headers });
    }
    return new Response(body, init);
  };
}

/** Хвост исключения JSONEachRow ровно в форме сервера 24.8: {"exception": "…"}. */
export function chJsonException(text: string): string {
  return `{"exception": ${JSON.stringify(text)}}`;
}
