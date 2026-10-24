import type { Metadata } from "next";
import { connection } from "next/server";
import ConsoleNotFound from "./(console)/not-found";

export const metadata: Metadata = { title: "Не найдено" };

/** 404 вне консоли (маршрут не совпал ни с одним сегментом). connection()
 *  делает страницу динамической: статический пререндер не получил бы nonce
 *  из CSP (src/proxy.ts), и его скрипты были бы заблокированы. */
export default async function RootNotFound() {
  await connection();
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md">
        <ConsoleNotFound />
      </div>
    </main>
  );
}
