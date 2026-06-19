import Link from "next/link";
import { ExportButton } from "@/components/ExportButton";
import { StatusBadge } from "@/components/StatusBadge";
import { WorkflowGateBanner } from "@/components/WorkflowGateBanner";
import { fetchTraceReplay, fetchWorkflowGate } from "@/lib/attest";
import type { WorkflowGate } from "@/lib/types";

type PageProps = { params: Promise<{ id: string }> };

export default async function TraceDetailPage({ params }: PageProps) {
  const { id } = await params;
  let replay: Awaited<ReturnType<typeof fetchTraceReplay>> | null = null;
  let gate: WorkflowGate | null = null;
  let error: string | null = null;

  try {
    [replay, gate] = await Promise.all([fetchTraceReplay(id), fetchWorkflowGate(id)]);
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load trace";
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <Link href="/" className="text-sm text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200">
            ← Back to traces
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight mt-2 font-mono text-sm sm:text-2xl break-all">
            {id}
          </h1>
        </div>
        <ExportButton traceId={id} />
      </div>

      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/30 p-4 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      ) : replay ? (
        <>
          {gate ? <WorkflowGateBanner gate={gate} /> : null}
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-zinc-600 dark:text-zinc-300">Chain integrity:</span>
            <StatusBadge ok={replay.all_verified} label={replay.all_verified ? "All verified" : "Tamper detected"} />
          </div>

          <div className="overflow-hidden rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
            <table className="min-w-full text-sm">
              <thead className="bg-zinc-50 dark:bg-zinc-800/50 text-left text-zinc-500">
                <tr>
                  <th className="px-4 py-3 font-medium">Seq</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Hash</th>
                  <th className="px-4 py-3 font-medium">Signature</th>
                  <th className="px-4 py-3 font-medium">Chain</th>
                  <th className="px-4 py-3 font-medium">Overall</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {replay.events.map((event) => (
                  <tr key={event.seq}>
                    <td className="px-4 py-3 font-mono">{event.seq}</td>
                    <td className="px-4 py-3">{event.type}</td>
                    <td className="px-4 py-3"><StatusBadge ok={event.hash_ok} /></td>
                    <td className="px-4 py-3"><StatusBadge ok={event.signature_ok} /></td>
                    <td className="px-4 py-3"><StatusBadge ok={event.chain_ok} /></td>
                    <td className="px-4 py-3"><StatusBadge ok={event.verified} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </div>
  );
}
