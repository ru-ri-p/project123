type StatusBadgeProps = {
  ok: boolean;
  label?: string;
};

export function StatusBadge({ ok, label }: StatusBadgeProps) {
  const text = label ?? (ok ? "Verified" : "Failed");
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
        ok
          ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300"
          : "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300"
      }`}
    >
      {text}
    </span>
  );
}
