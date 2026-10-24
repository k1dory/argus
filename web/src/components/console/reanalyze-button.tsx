"use client";

import { useActionState, useEffect } from "react";
import { RefreshCw } from "lucide-react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import { reanalyzeAction } from "@/lib/incident-actions";
import { Button } from "@/components/ui/button";

const initial: FormState = { error: null };

export function ReanalyzeButton({ incidentId }: { incidentId: string }) {
  const [state, action, pending] = useActionState(reanalyzeAction, initial);
  useEffect(() => {
    if (state.ok) toast.success("Переразбор запущен", { description: "обновите карточку через несколько секунд" });
    else if (state.error) toast.error(state.error);
  }, [state]);
  return (
    <form action={action} className="flex flex-wrap items-center gap-3" aria-busy={pending}>
      <input type="hidden" name="incident_id" value={incidentId} />
      <Button type="submit" variant="secondary" size="sm" disabled={pending}>
        {pending ? <span className="ascii-spin" aria-hidden /> : <RefreshCw strokeWidth={1.5} />}
        {pending ? "Запуск…" : "Переразобрать моделью"}
      </Button>
      {state.error && <span role="alert" className="font-mono text-xs text-destructive">{state.error}</span>}
      {state.ok && <span role="status" className="font-mono text-xs text-[var(--status-ok)]">запущено — обновите карточку через несколько секунд</span>}
    </form>
  );
}
