import Link from "next/link";
import { ApprovalActions } from "@/components/ApprovalActions";
import { StatusBadge } from "@/components/StatusBadge";
import { fetchApprovals } from "@/lib/attest";

export default async function ApprovalsPage() {
  let pending: Awaited<ReturnType<typeof fetchApprovals>> = [];
  let error: string | null = null;

  try {
    pending = await fetchApprovals("pending");
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load approvals";
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Approvals queue</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Pending human review — Approve or Deny records an <code className="font-mono">approval_action</code> event.
        </p>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/30 p-4 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      ) : null}

      <div className="space-y-4">
        {pending.length === 0 ? (
          <div className="rounded-xl border border-dashed border-zinc-300 dark:border-zinc-700 p-8 text-center text-zinc-500 text-sm">
            No pending approvals. Seed one with{" "}
            <code className="font-mono">python scripts/seed_pending_approval.py --trace-id &lt;uuid&gt;</code>
          </div>
        ) : (
          pending.map((approval) => (
            <article
              key={approval.id}
              className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-4 shadow-sm space-y-3"
            >
              <div className="flex flex-wrap items-center gap-2 justify-between">
                <div>
                  <p className="text-xs text-zinc-500">Trace</p>
                  <Link
                    href={`/traces/${approval.trace_id}`}
                    className="font-mono text-sm text-blue-600 dark:text-blue-400 hover:underline break-all"
                  >
                    {approval.trace_id}
                  </Link>
                </div>
                <StatusBadge ok={false} label="Pending" />
              </div>
              <p className="text-xs text-zinc-500">
                Requested {new Date(approval.created_at).toLocaleString()}
              </p>
              <ApprovalActions approvalId={approval.id} />
            </article>
          ))
        )}
      </div>
    </div>
  );
}
