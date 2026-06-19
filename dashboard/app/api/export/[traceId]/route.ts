import { evidenceExportHeaders, evidenceExportUrl } from "@/lib/attest";
import { NextRequest, NextResponse } from "next/server";

type RouteParams = { params: Promise<{ traceId: string }> };

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { traceId } = await params;
  const format = request.nextUrl.searchParams.get("format") === "json" ? "json" : "zip";

  const response = await fetch(evidenceExportUrl(traceId, format), {
    headers: evidenceExportHeaders(),
    cache: "no-store",
  });

  if (!response.ok) {
    const text = await response.text();
    return NextResponse.json({ error: text }, { status: response.status });
  }

  const body = await response.arrayBuffer();
  const contentType = format === "zip" ? "application/zip" : "application/json";
  return new NextResponse(body, {
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": `attachment; filename="attest-evidence-${traceId}.${format === "zip" ? "zip" : "json"}"`,
    },
  });
}
