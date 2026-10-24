/** URL поиска используются и серверными страницами, и клиентскими кнопками. */
export const searchHref = {
  srcip: (ip: string) => `/search?q=${encodeURIComponent(`srcip:${ip}`)}`,
  rule: (id: string | number) => `/search?q=${encodeURIComponent(`rule:${id}`)}`,
  agent: (name: string) => `/search?q=${encodeURIComponent(`agent:${name}`)}`,
  // События единой схемы — в журнал: источник и хост там структурные фильтры.
  eventSrc: (ip: string) => `/events?q=${encodeURIComponent(`src:${ip}`)}`,
  source: (s: string) => `/events?source=${encodeURIComponent(s)}`,
  actor: (a: string) => `/events?q=${encodeURIComponent(`actor:${a}`)}`,
  node: (n: string) => `/events?host=${encodeURIComponent(n)}`,
};
