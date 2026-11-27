import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ruleLevelLabel } from "@/lib/shared/labels";
import { TONE_CLASS, ruleLevelTone } from "./tone";

/** Уровень правила Wazuh: тонированный бейдж + текст «уровень n», никогда не только цвет. */
export function SeverityBadge({ level }: { level: number }) {
  return <Badge variant="outline" className={cn("font-sans tabular-nums", TONE_CLASS[ruleLevelTone(level)])}>{ruleLevelLabel(level)}</Badge>;
}
