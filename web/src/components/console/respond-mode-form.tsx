"use client";

import { useActionState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import type { FormState } from "@/lib/actions";
import { RESPOND_MODES, type RespondMode, type RespondModeFrom } from "@/lib/shared/respond";
import { setRespondModeAction } from "@/lib/respond-actions";

/** Переключатель IPS/IDS. requested — что уже записано из консоли, но движок ещё не подтвердил. */
export function RespondModeForm({ current, from, requested }: { current: RespondMode; from: RespondModeFrom; requested?: RespondMode | "" | null }) {
  const [state, action, pending] = useActionState(setRespondModeAction, { error: null } as FormState);
  const waiting = requested !== undefined && requested !== null && requested !== current && (requested !== "" || from === "console");
  return (
    <form action={action} className="space-y-3">
      <fieldset className="space-y-2">
        <legend className="c-label mb-2">режим реагирования</legend>
        <RadioGroup name="mode" defaultValue={requested || current} className="gap-2">
          {(Object.keys(RESPOND_MODES) as RespondMode[]).map((m) => (
            <Label key={m} htmlFor={`mode-${m}`} className="flex cursor-pointer items-start gap-3 border border-border bg-[var(--surface-deep)] px-3 py-2 font-normal">
              <RadioGroupItem id={`mode-${m}`} value={m} className="mt-0.5" />
              <span>
                <span className="c-label block">{RESPOND_MODES[m].label}</span>
                <span className="text-xs text-muted-foreground">{RESPOND_MODES[m].hint}</span>
              </span>
            </Label>
          ))}
        </RadioGroup>
      </fieldset>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={pending} size="sm">{pending ? "Сохранение…" : "Применить"}</Button>
        {from === "console" && (
          <Button type="submit" name="reset" value="1" variant="secondary" size="sm" disabled={pending}>Вернуть режим из конфига</Button>
        )}
        <p className="text-xs text-muted-foreground">
          источник режима: {from === "console" ? "консоль (переживает рестарт движка)" : "argus.analyst.yml"}
          {waiting && ` · запрошено «${requested ? RESPOND_MODES[requested as RespondMode].label : "из конфига"}», движок применит в течение цикла`}
        </p>
      </div>
      {state.error && <p className="text-xs text-destructive">{state.error}</p>}
      {state.ok && <p className="text-xs text-[var(--status-ok)]">Сохранено — движок подхватит режим на следующем цикле</p>}
    </form>
  );
}
