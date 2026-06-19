import { StatusBadge } from "./StatusBadge";
import type { WorkflowGate } from "@/lib/types";

type WorkflowGateBannerProps = {
  gate: WorkflowGate;
};

export function WorkflowGateBanner({ gate }: WorkflowGateBannerProps) {
  const ok = gate.resume_allowed;
  const label =
    gate.workflow_status === "proceed"
      ? "May proceed"
      : gate.workflow_status === "blocked_pending_approval"
        ? "Awaiting approval"
        : gate.workflow_status === "blocked_denied"
          ? "Denied — aborted"
          : "Blocked";

  return (
    <div
      className={`rounded-xl border p-4 space-y-2 ${
        ok
          ? "border-emerald-200 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30"
          : "border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/30"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">Workflow gate</span>
        <StatusBadge ok={ok} label={label} />
        {gate.policy_tier ? (
          <span className="text-xs text-zinc-500">Policy tier: {gate.policy_tier}</span>
        ) : null}
      </div>
      <p className="text-sm text-zinc-700 dark:text-zinc-300">{gate.message}</p>
      {gate.policy_reasons && gate.policy_reasons.length > 0 ? (
        <ul className="text-xs text-zinc-500 list-disc list-inside">
          {gate.policy_reasons.slice(0, 3).map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {gate.approval_id && gate.approval_status === "pending" ? (
        <a
          href="/approvals"
          className="inline-block text-sm text-blue-600 dark:text-blue-400 hover:underline"
        >
          Open approvals queue →
        </a>
      ) : null}
    </div>
  );
}
