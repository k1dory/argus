// Транспорт ClickHouse 24.8 для тестов: тело с исключением в конце (так сервер отвечает
// без wait_end_of_query) превращается в HTTP 500 с X-ClickHouse-Exception-Code, если
// клиент прислал wait_end_of_query=1 — проверено на живом 24.8. Без параметра — исходный
// ответ 200: клиент, забывший параметр, получит строку исключения как данные и тест упадёт.
const EXCEPTION_LINE = /(?:^|\{"exception":\s*")(?:Poco::Exception\. |std::exception\. )?Code:\s*(\d+)[.,][^\n]*/m;

export function chHttp(body: string, init: ResponseInit = {}) {
  return async (input: URL | string | Request): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const m = EXCEPTION_LINE.exec(body);
    if (url.searchParams.get("wait_end_of_query") === "1" && m && (init.status ?? 200) === 200) {
      const headers = new Headers(init.headers);
      headers.set("X-ClickHouse-Exception-Code", m[1]);
      return new Response(m[0] + "\n", { status: 500, headers });
    }
    return new Response(body, init);
  };
}
