"use client";

// Защита несохранённых правок при переходах внутри приложения: beforeunload
// ловит только закрытие вкладки, а ссылки навигации, «К дашборду» и кнопка
// «Назад» браузера уводили без вопроса. Пока dirty:
// - клик по внутренней ссылке перехватывается в capture-фазе на document;
// - «Назад»/«Вперёд» браузера: поверх текущей записи истории кладётся
//   её копия, popstate возвращает пользователя и открывает тот же диалог.
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { guardedHref } from "@/lib/shared/dashboard-view";
import {
  AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";

const BACK = "__back";

export function useUnsavedGuard(dirty: boolean, onSave: () => void) {
  const router = useRouter();
  const [target, setTarget] = useState<string | null>(null);
  const dirtyRef = useRef(dirty);
  const trapRef = useRef(false);
  // Переход, отложенный до успешного сохранения из диалога.
  const [afterSave, setAfterSave] = useState<string | null>(null);

  useEffect(() => {
    dirtyRef.current = dirty;
  }, [dirty]);

  // Закрытие вкладки и перезагрузка.
  useEffect(() => {
    if (!dirty) return;
    const onUnload = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", onUnload);
    return () => window.removeEventListener("beforeunload", onUnload);
  }, [dirty]);

  // Клики по ссылкам внутри приложения.
  useEffect(() => {
    if (!dirty) return;
    const onClick = (e: MouseEvent) => {
      const el = e.target instanceof Element ? e.target.closest("a[href]") : null;
      const a = el instanceof HTMLAnchorElement ? el : null;
      const href = guardedHref(e, a ? { href: a.href, target: a.target, download: a.hasAttribute("download") } : null, window.location);
      if (!href) return;
      e.preventDefault();
      e.stopPropagation();
      setTarget(href);
    };
    document.addEventListener("click", onClick, true);
    return () => document.removeEventListener("click", onClick, true);
  }, [dirty]);

  // «Назад» браузера: ловушка-копия текущей записи истории.
  useEffect(() => {
    if (!dirty) return;
    if (!trapRef.current) {
      window.history.pushState(window.history.state, "", window.location.href);
      trapRef.current = true;
    }
    const onPop = () => {
      if (!dirtyRef.current || !trapRef.current) return;
      window.history.pushState(window.history.state, "", window.location.href);
      setTarget(BACK);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [dirty]);

  const go = useCallback((href: string) => {
    dirtyRef.current = false;
    if (href === BACK) {
      // Ловушка и запись, с которой пришли, — две записи назад.
      const steps = trapRef.current ? 2 : 1;
      trapRef.current = false;
      window.history.go(-steps);
    } else {
      router.push(href);
    }
  }, [router]);

  /** Вызывать после успешного сохранения: если ждали — уходим. */
  const saved = useCallback(() => {
    if (afterSave) {
      const href = afterSave;
      setAfterSave(null);
      go(href);
    }
  }, [afterSave, go]);

  const dialog = (
    <AlertDialog open={target !== null} onOpenChange={(o) => !o && setTarget(null)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Есть несохранённые правки</AlertDialogTitle>
          <AlertDialogDescription>Если уйти сейчас, изменения панелей и запросов пропадут.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Остаться</AlertDialogCancel>
          <Button variant="secondary" onClick={() => { const t = target; setTarget(null); if (t) go(t); }}>Уйти без сохранения</Button>
          <Button onClick={() => { setAfterSave(target); setTarget(null); onSave(); }}>Сохранить и уйти</Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );

  return { dialog, saved, pendingAfterSave: afterSave !== null, cancelAfterSave: () => setAfterSave(null) };
}
