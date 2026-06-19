import Link from "next/link";
import { fetchTraces } from "@/lib/attest";

export default async function TracesPage() {
  let traces: Awaited<ReturnType<typeof fetchTraces>> = [];
  let error: string | null = null;

  try {
    traces = await fetchTraces();
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load traces";
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Traces</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Org-scoped provenance records — open a trace to verify replay integrity.
        </p>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/30 p-4 text-sm text-red-800 dark:text-red-200">
          {error}. Ensure the API is running at{" "}
          <code className="font-mono">http://127.0.0.1:8000</code>.
        </div>
      ) : null}

      <div className="overflow-hidden rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
        <table className="min-w-full text-sm">
          <thead className="bg-zinc-50 dark:bg-zinc-800/50 text-left text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-medium">Trace ID</th>
              <th className="px-4 py-3 font-medium">Created</th>
              <th className="px-4 py-3 font-medium">Events</th>
              <th className="px-4 py-3 font-medium">Policy</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {traces.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-zinc-500">
                  No traces yet. Record events via <code className="font-mono">POST /v1/event</code>.
                </td>
              </tr>
            ) : (
              traces.map((trace) => (
                <tr key={trace.trace_id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/30">
                  <td className="px-4 py-3">
                    <Link
                      href={`/traces/${trace.trace_id}`}
                      className="font-mono text-xs text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      {trace.trace_id}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-zinc-600 dark:text-zinc-300">
                    {new Date(trace.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">{trace.event_count}</td>
                  <td className="px-4 py-3 text-zinc-500">{trace.policy_version || "—"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
