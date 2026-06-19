import { resolveApproval } from "@/lib/attest";
import { NextRequest, NextResponse } from "next/server";

type RouteParams = { params: Promise<{ id: string }> };

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const body = (await request.json()) as {
    status: "approved" | "denied";
    approver_id: string;
    comment?: string;
  };

  try {
    await resolveApproval(id, body);
    return NextResponse.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "resolve failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
