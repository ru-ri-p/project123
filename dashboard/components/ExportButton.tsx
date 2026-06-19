"use client";

type ExportButtonProps = {
  traceId: string;
};

export function ExportButton({ traceId }: ExportButtonProps) {
  async function download(format: "json" | "zip") {
    const response = await fetch(`/api/export/${traceId}?format=${format}`);
    if (!response.ok) {
      alert("Export failed");
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `attest-evidence-${traceId}.${format === "zip" ? "zip" : "json"}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-wrap gap-2">
      <button
        type="button"
        onClick={() => download("zip")}
        className="rounded-md bg-zinc-900 text-white px-4 py-2 text-sm font-medium hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white transition-colors"
      >
        Export ZIP
      </button>
      <button
        type="button"
        onClick={() => download("json")}
        className="rounded-md border border-zinc-300 dark:border-zinc-600 px-4 py-2 text-sm font-medium hover:bg-zinc-50 dark:hover:bg-zinc-900 transition-colors"
      >
        Export JSON
      </button>
    </div>
  );
}
