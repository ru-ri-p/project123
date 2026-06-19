export type TraceSummary = {
  trace_id: string;
  created_at: string;
  policy_version: string;
  event_count: number;
};

export type EventReplayItem = {
  seq: number;
  type: string;
  verified: boolean;
  hash_ok: boolean;
  signature_ok: boolean;
  chain_ok: boolean;
};

export type TraceReplay = {
  trace_id: string;
  all_verified: boolean;
  events: EventReplayItem[];
};

export type WorkflowGate = {
  trace_id: string;
  workflow_status: string;
  resume_allowed: boolean;
  approval_id: string | null;
  approval_status: string | null;
  approver_id?: string | null;
  policy_tier?: string | null;
  policy_reasons?: string[];
  message: string;
};

export type Approval = {
  id: string;
  trace_id: string;
  event_id: string | null;
  status: string;
  approver_id: string | null;
  comment: string | null;
  created_at: string;
  resolved_at: string | null;
};
