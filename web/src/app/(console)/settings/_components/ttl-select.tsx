"use client";

import { useState } from "react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EXCLUDE_TTLS } from "@/lib/shared/respond";

/** Срок исключения адреса: shadcn Select + скрытое поле ttl для формы. */
export function TtlSelect({ id }: { id: string }) {
  const [ttl, setTtl] = useState<string>("24h");
  return (
    <>
      <input type="hidden" name="ttl" value={ttl} />
      <Select value={ttl} onValueChange={setTtl}>
        <SelectTrigger id={id} className="h-9 w-full"><SelectValue /></SelectTrigger>
        <SelectContent>
          {EXCLUDE_TTLS.map((t) => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
        </SelectContent>
      </Select>
    </>
  );
}
