"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type ApprovalActionsProps = {
  approvalId: string;
};

export function ApprovalActions({ approvalId }: ApprovalActionsProps) {
  const router = useRouter();
  const [loading, setLoading] = useState<"approved" | "denied" | null>(null);
  const [comment, setComment] = useState("");

  async function resolve(status: "approved" | "denied") {
    setLoading(status);
    try {
      const response = await fetch(`/api/approvals/${approvalId}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status,
          approver_id: "dashboard_user",
          comment: comment || undefined,
        }),
      });
      if (!response.ok) {
        const text = await response.text();
        alert(`Action failed: ${text}`);
        return;
      }
      router.refresh();
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <input
        type="text"
        placeholder="Comment (optional)"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        className="rounded-md border border-zinc-300 dark:border-zinc-600 bg-transparent px-3 py-2 text-sm w-full sm:max-w-xs"
      />
      <div className="flex gap-2">
        <button
          type="button"
          disabled={loading !== null}
          onClick={() => resolve("approved")}
          className="rounded-md bg-emerald-600 text-white px-3 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
        >
          {loading === "approved" ? "…" : "Approve"}
        </button>
        <button
          type="button"
          disabled={loading !== null}
          onClick={() => resolve("denied")}
          className="rounded-md bg-red-600 text-white px-3 py-2 text-sm font-medium hover:bg-red-500 disabled:opacity-50"
        >
          {loading === "denied" ? "…" : "Deny"}
        </button>
      </div>
    </div>
  );
}
