"use client";

import { useActionState, useEffect } from "react";
import { RotateCcw } from "lucide-react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import { reopenTriageAction } from "@/lib/incident-actions";
import { Button } from "@/components/ui/button";

const initial: FormState = { error: null };

/** Снять отметку «вердикт агента записан»: следующий запуск агента разбора
 *  по инциденту получит сессию. */
export function TriageReopenButton({ incidentId }: { incidentId: string }) {
  const [state, action, pending] = useActionState(reopenTriageAction, initial);
  useEffect(() => {
    if (state.ok) toast.success("Повторный разбор разрешён", { description: "следующая сессия агента по инциденту будет выдана" });
    else if (state.error) toast.error(state.error);
  }, [state]);
  return (
    <form action={action} className="flex flex-wrap items-center gap-3" aria-busy={pending}>
      <input type="hidden" name="incident_id" value={incidentId} />
      <Button type="submit" variant="secondary" size="sm" disabled={pending}>
        {pending ? <span className="ascii-spin" aria-hidden /> : <RotateCcw strokeWidth={1.5} />}
        {pending ? "Запись…" : "Разрешить повторный разбор"}
      </Button>
      {state.error && <span role="alert" className="font-mono text-xs text-destructive">{state.error}</span>}
    </form>
  );
}
