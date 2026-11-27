"use client";

import { useActionState, useState } from "react";
import { Plus } from "lucide-react";
import { createDashboardAction } from "@/lib/dashboard-actions";
import type { FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/** Форма «Название → Создать»; после создания action уводит в редактор. */
export function CreateDashboardForm({ onCancel }: { onCancel?: () => void }) {
  const [state, action, pending] = useActionState(createDashboardAction, { error: null } as FormState);
  return (
    <form action={action} className="space-y-4" aria-busy={pending}>
      <div className="space-y-2">
        <Label htmlFor="dash-title">Название</Label>
        <Input id="dash-title" name="title" placeholder="Например, «Входы администраторов»" required minLength={2} maxLength={120} autoFocus className="h-10 w-full px-3" disabled={pending} aria-describedby={state.error ? "dash-title-error" : undefined} aria-invalid={state.error ? true : undefined} />
        {state.error && <p id="dash-title-error" role="alert" className="text-xs text-destructive">{state.error}</p>}
      </div>
      <DialogFooter>
        {onCancel && <Button type="button" variant="ghost" onClick={onCancel} disabled={pending}>Отмена</Button>}
        <Button type="submit" disabled={pending}>
          {pending ? <span className="ascii-spin" aria-hidden /> : <Plus strokeWidth={1.5} />}
          {pending ? "Создание…" : "Создать"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/** Кнопка в шапке списка: открывает диалог с названием. */
export function CreateDashboardButton() {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm"><Plus strokeWidth={1.5} />Новый дашборд</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Новый дашборд</DialogTitle>
          <DialogDescription>Дашборд откроется в редакторе с одной панелью — событиями по классам. Её можно поменять или удалить.</DialogDescription>
        </DialogHeader>
        <CreateDashboardForm onCancel={() => setOpen(false)} />
      </DialogContent>
    </Dialog>
  );
}
