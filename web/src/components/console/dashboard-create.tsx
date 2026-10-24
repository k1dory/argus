"use client";

import { useActionState } from "react";
import { Plus } from "lucide-react";
import { createDashboardAction } from "@/lib/dashboard-actions";
import type { FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function CreateDashboardForm() {
  const [state, action, pending] = useActionState(createDashboardAction, { error: null } as FormState);
  return (
    <form action={action} className="flex flex-wrap items-end gap-3" aria-busy={pending}>
      <div className="space-y-1">
        <Label htmlFor="dash-title" className="c-label">Новый дашборд</Label>
        <Input id="dash-title" name="title" placeholder="Название" required minLength={2} maxLength={120} className="h-10 w-72 px-3" disabled={pending} aria-describedby={state.error ? "dash-title-error" : undefined} aria-invalid={state.error ? true : undefined} />
      </div>
      <Button type="submit" variant="secondary" className="min-h-10" disabled={pending}>
        {pending ? <span className="ascii-spin" aria-hidden /> : <Plus strokeWidth={1.5} />}
        {pending ? "Создание…" : "Создать"}
      </Button>
      {state.error && <span id="dash-title-error" role="alert" className="font-mono text-xs text-destructive">{state.error}</span>}
    </form>
  );
}
