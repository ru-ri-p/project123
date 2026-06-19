import type { Approval, TraceReplay, TraceSummary, WorkflowGate } from "./types";

const API_BASE = process.env.ATTEST_API_URL ?? "http://127.0.0.1:8000";
const API_KEY = process.env.ATTEST_API_KEY ?? "org_demo_key";

function headers(): HeadersInit {
  return {
    "x-api-key": API_KEY,
    Accept: "application/json",
  };
}

async function parseJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Attest API ${response.status}: ${body}`);
  }
  return response.json() as Promise<T>;
}

export async function fetchTraces(): Promise<TraceSummary[]> {
  const response = await fetch(`${API_BASE}/v1/traces`, {
    headers: headers(),
    cache: "no-store",
  });
  return parseJson<TraceSummary[]>(response);
}

export async function fetchWorkflowGate(traceId: string): Promise<WorkflowGate> {
  const response = await fetch(`${API_BASE}/v1/trace/${traceId}/gate`, {
    headers: headers(),
    cache: "no-store",
  });
  return parseJson<WorkflowGate>(response);
}

export async function fetchTraceReplay(traceId: string): Promise<TraceReplay> {
  const response = await fetch(`${API_BASE}/v1/trace/${traceId}/replay`, {
    headers: headers(),
    cache: "no-store",
  });
  return parseJson<TraceReplay>(response);
}

export async function fetchApprovals(status?: string): Promise<Approval[]> {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  const response = await fetch(`${API_BASE}/v1/approvals${query}`, {
    headers: headers(),
    cache: "no-store",
  });
  return parseJson<Approval[]>(response);
}

export async function resolveApproval(
  approvalId: string,
  body: { status: "approved" | "denied"; approver_id: string; comment?: string },
): Promise<void> {
  const response = await fetch(`${API_BASE}/v1/approvals/${approvalId}/resolve`, {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Resolve failed (${response.status}): ${text}`);
  }
}

export function evidenceExportUrl(traceId: string, format: "json" | "zip" = "zip"): string {
  return `${API_BASE}/v1/evidence/${traceId}/export?format=${format}`;
}

export function evidenceExportHeaders(): HeadersInit {
  return headers();
}
