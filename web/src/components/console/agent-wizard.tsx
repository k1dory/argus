"use client";

// Мастер добавления агента Wazuh: команда установки под ОС, как в Wazuh dashboard
// («Deploy new agent»). Пароль регистрации не хранится и не подставляется —
// команда просит ввести его на хосте.
import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type Os = "deb" | "rpm" | "windows" | "macos";
const OS: { v: Os; l: string }[] = [
  { v: "deb", l: "Debian / Ubuntu (deb, amd64)" },
  { v: "rpm", l: "RHEL / Rocky / Alma (rpm, x86_64)" },
  { v: "windows", l: "Windows (msi, PowerShell)" },
  { v: "macos", l: "macOS (pkg, Apple Silicon)" },
];

const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

/** Команды из документации Wazuh 4.x (packages.wazuh.com), версия — как у менеджера. */
function command(os: Os, v: string, manager: string, name: string, group: string, withPassword: boolean): string {
  const env = [`WAZUH_MANAGER=${q(manager)}`, group && `WAZUH_AGENT_GROUP=${q(group)}`, name && `WAZUH_AGENT_NAME=${q(name)}`, withPassword && `WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD"`]
    .filter(Boolean)
    .join(" ");
  const ask = withPassword ? `read -rs -p "Пароль регистрации агента: " REG_PASSWORD && echo && ` : "";
  switch (os) {
    case "deb":
      return `${ask}wget -q https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${v}-1_amd64.deb && sudo ${env} dpkg -i ./wazuh-agent_${v}-1_amd64.deb && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`;
    case "rpm":
      return `${ask}curl -fsSo wazuh-agent-${v}-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-${v}-1.x86_64.rpm && sudo ${env} rpm -ihv wazuh-agent-${v}-1.x86_64.rpm && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`;
    case "macos":
      return `${ask}curl -fsSo wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-${v}-1.arm64.pkg && echo "${env}" | sudo tee /tmp/wazuh_envs >/dev/null && sudo installer -pkg ./wazuh-agent.pkg -target / && sudo /Library/Ossec/bin/wazuh-control start`;
    case "windows": {
      const props = [`WAZUH_MANAGER="${manager}"`, group && `WAZUH_AGENT_GROUP="${group}"`, name && `WAZUH_AGENT_NAME="${name}"`, withPassword && `WAZUH_REGISTRATION_PASSWORD="$RegPassword"`].filter(Boolean).join(" ");
      const askPs = withPassword ? `$RegPassword = Read-Host -Prompt 'Пароль регистрации агента'; ` : "";
      return `${askPs}Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-${v}-1.msi -OutFile $env:tmp\\wazuh-agent.msi; msiexec.exe /i $env:tmp\\wazuh-agent.msi /q ${props}; NET START WazuhSvc`;
    }
  }
}

/** version — как у менеджера (пусто, если API недоступен: команду тогда не
 *  собираем — вымышленная версия поставила бы агента не той сборки).
 *  managerHost страница передаёт только аналитику и выше: адрес API Wazuh
 *  наблюдателю не раскрывается. */
export function AgentWizard({ version, managerHost, groups, passwordRequired }: { version: string; managerHost: string; groups: string[]; passwordRequired: boolean }) {
  const [os, setOs] = useState<Os>("deb");
  const [manager, setManager] = useState(managerHost);
  const [name, setName] = useState("");
  const [group, setGroup] = useState(groups.includes("default") ? "default" : (groups[0] ?? ""));
  const [copied, setCopied] = useState(false);
  const v = /^\d+\.\d+\.\d+$/.test(version.replace(/^v/, "")) ? version.replace(/^v/, "") : "";
  const cmd = manager && v ? command(os, v, manager, name.trim(), group, passwordRequired) : "";

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* буфер недоступен (http без TLS) — команду можно выделить руками */
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid min-w-0 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="min-w-0 space-y-2">
          <Label htmlFor="agent-os" className="c-label">ОС хоста</Label>
          <Select value={os} onValueChange={(x) => setOs(x as Os)}>
            <SelectTrigger id="agent-os" className="h-9 w-full min-w-0 overflow-hidden"><SelectValue /></SelectTrigger>
            <SelectContent>{OS.map((o) => <SelectItem key={o.v} value={o.v}>{o.l}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="min-w-0 space-y-2">
          <Label htmlFor="agent-manager" className="c-label">Адрес менеджера</Label>
          <Input id="agent-manager" value={manager} onChange={(e) => setManager(e.target.value.trim())} placeholder="wazuh.example.org" className="h-9 px-3 font-mono" />
        </div>
        <div className="min-w-0 space-y-2">
          <Label htmlFor="agent-name" className="c-label">Имя агента (пусто — hostname)</Label>
          <Input id="agent-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" className="h-9 px-3 font-mono" />
        </div>
        <div className="min-w-0 space-y-2">
          <Label htmlFor="agent-group" className="c-label">Группа</Label>
          {groups.length > 0 ? (
            <Select value={group} onValueChange={setGroup}>
              <SelectTrigger id="agent-group" className="h-9 w-full min-w-0 overflow-hidden"><SelectValue /></SelectTrigger>
              <SelectContent>{groups.map((g) => <SelectItem key={g} value={g}>{g}</SelectItem>)}</SelectContent>
            </Select>
          ) : (
            <Input id="agent-group" value={group} onChange={(e) => setGroup(e.target.value.trim())} placeholder="default" className="h-9 px-3 font-mono" />
          )}
        </div>
      </div>
      {cmd ? (
        <>
          <pre className="c-well overflow-x-auto p-3 font-mono text-[12px] leading-[1.5] whitespace-pre-wrap break-all">{cmd}</pre>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" variant="secondary" size="sm" onClick={copy}>{copied ? <Check strokeWidth={1.5} /> : <Copy strokeWidth={1.5} />}{copied ? "Скопировано" : "Копировать команду"}</Button>
            <span className="font-mono text-xs text-muted-foreground">
              Wazuh {v} · порты 1514/tcp (события) и 1515/tcp (регистрация) до менеджера
              {passwordRequired && " · менеджер требует пароль регистрации — команда спросит его"}
            </span>
          </div>
        </>
      ) : !v ? (
        <p role="status" className="text-sm text-[var(--status-warn)]">Версия менеджера неизвестна (Wazuh API недоступен) — команда установки заблокирована: агент должен совпадать по версии с менеджером.</p>
      ) : (
        <p className="text-sm text-muted-foreground">Укажите адрес менеджера (или задайте WAZUH_MANAGER_HOST в .env).</p>
      )}
    </div>
  );
}
