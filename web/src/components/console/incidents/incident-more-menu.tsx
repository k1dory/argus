"use client";

// Меню «⋯» карточки инцидента: обновить данные и выгрузки (JSON, Markdown).
// Второстепенное убрано из шапки, чтобы там осталось одно главное действие.
import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { Download, Ellipsis, RotateCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { fetchDownload, saveBlob } from "@/lib/shared/download";

export function IncidentMoreMenu({ id }: { id: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const download = async (href: string, filename: string) => {
    try {
      saveBlob(await fetchDownload(href), filename);
      toast.success("Файл готов", { description: filename });
    } catch (e) {
      toast.error("Экспорт не выполнен", { description: e instanceof Error ? e.message : String(e) });
    }
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button type="button" variant="secondary" size="sm" aria-label="Ещё действия" aria-busy={pending || undefined}>
          {pending ? <span className="ascii-spin" aria-hidden /> : <Ellipsis strokeWidth={1.5} />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => start(() => router.refresh())}><RotateCw strokeWidth={1.5} />Обновить данные</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void download(`/api/incidents/${id}`, `${id}.json`)}><Download strokeWidth={1.5} />Скачать JSON</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void download(`/api/incidents/${id}/markdown`, `${id}.md`)}><Download strokeWidth={1.5} />Скачать Markdown</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
