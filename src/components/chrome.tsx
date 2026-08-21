import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { DiffLine, FindingStatus, Severity } from "@/lib/types";

/* ---------------------------------- logo ---------------------------------- */

export function Logo({ className }: { className?: string }) {
  return (
    <Link to="/" className={cn("flex items-center gap-2", className)}>
      <span className="size-2 rounded-full bg-accent" />
      <span className="font-mono text-sm font-semibold tracking-tight text-foreground">
        SecureLoop
      </span>
    </Link>
  );
}

/* ------------------------------- pill button ------------------------------ */

export function Pill({
  children,
  variant = "solid",
  dot = true,
  className,
  ...rest
}: {
  children: ReactNode;
  variant?: "solid" | "outline";
  dot?: boolean;
  className?: string;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "pill-hover inline-flex cursor-pointer items-center gap-2.5 rounded-full border px-5 py-2.5 font-mono text-xs font-medium tracking-wide",
        variant === "solid"
          ? "border-border bg-elevated text-foreground"
          : "border-border bg-transparent text-subtle hover:text-foreground",
        className,
      )}
      {...rest}
    >
      {dot && (
        <span
          className={cn(
            "size-1.5 rounded-full",
            variant === "solid" ? "bg-accent" : "bg-subtle",
          )}
        />
      )}
      {children}
    </button>
  );
}

export function PillLink({
  to,
  params,
  children,
  variant = "solid",
  dot = true,
  className,
}: {
  to: string;
  params?: Record<string, string>;
  children: ReactNode;
  variant?: "solid" | "outline";
  dot?: boolean;
  className?: string;
}) {
  return (
    <Link
      to={to}
      {...(params ? { params } : {})}
      className={cn(
        "pill-hover inline-flex items-center gap-2.5 rounded-full border px-5 py-2.5 font-mono text-xs font-medium tracking-wide",
        variant === "solid"
          ? "border-border bg-elevated text-foreground"
          : "border-border bg-transparent text-subtle hover:text-foreground",
        className,
      )}
    >
      {dot && (
        <span
          className={cn(
            "size-1.5 rounded-full",
            variant === "solid" ? "bg-accent" : "bg-subtle",
          )}
        />
      )}
      {children}
    </Link>
  );
}

/* --------------------------------- eyebrow -------------------------------- */

export function Eyebrow({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <p className={cn("eyebrow", className)}>{children}</p>;
}

/* ----------------------------- terminal window ---------------------------- */

export function TerminalWindow({
  title,
  children,
  className,
  bodyClassName,
}: {
  title: string;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border border-border bg-elevated",
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <span className="size-2.5 rounded-full bg-border" />
        <span className="size-2.5 rounded-full bg-border" />
        <span className="size-2.5 rounded-full bg-border" />
        <span className="mx-auto font-mono text-[11px] text-subtle">
          {title}
        </span>
        <span className="w-14" />
      </div>
      <div
        className={cn(
          "overflow-x-auto p-4 font-mono text-xs leading-relaxed",
          bodyClassName,
        )}
      >
        {children}
      </div>
    </div>
  );
}

/* --------------------------------- badges --------------------------------- */

const severityStyles: Record<Severity, string> = {
  critical: "border-danger/40 text-danger",
  high: "border-accent/40 text-accent",
  medium: "border-warning/40 text-warning",
  low: "border-border text-subtle",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        severityStyles[severity],
      )}
    >
      <span className="size-1 rounded-full bg-current" />
      {severity}
    </span>
  );
}

const statusStyles: Record<FindingStatus, string> = {
  open: "border-border text-subtle",
  explained: "border-border text-subtle",
  patched: "border-warning/40 text-warning",
  validated: "border-success/40 text-success",
  accepted: "border-success/40 text-success",
  rejected: "border-danger/40 text-danger",
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        statusStyles[status],
      )}
    >
      <span className="size-1 rounded-full bg-current" />
      {status}
    </span>
  );
}

/* ------------------------------- diff viewer ------------------------------ */

export function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <div className="font-mono text-xs leading-relaxed">
      {lines.map((l, i) => (
        <div
          key={i}
          className={cn(
            "whitespace-pre px-3 py-0.5",
            l.type === "add" && "bg-success/10 text-success",
            l.type === "del" && "bg-danger/10 text-danger",
            l.type === "hunk" && "text-subtle",
            l.type === "ctx" && "text-foreground/70",
          )}
        >
          {l.code}
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ code snippet ------------------------------ */

export function CodeView({
  lines,
}: {
  lines: { n: number; code: string; vuln?: boolean }[];
}) {
  return (
    <div className="font-mono text-xs leading-relaxed">
      {lines.map((l) => (
        <div
          key={l.n}
          className={cn(
            "flex whitespace-pre px-3 py-0.5",
            l.vuln ? "bg-danger/10 text-foreground" : "text-foreground/70",
          )}
        >
          <span className="w-8 shrink-0 select-none text-right text-subtle/60">
            {l.n}
          </span>
          <span className="pl-4">
            {l.vuln && <span className="mr-2 text-danger">▸</span>}
            {l.code}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ score ring -------------------------------- */

export function ScoreBadge({ score, size = "md" }: { score: number; size?: "sm" | "md" }) {
  const tone =
    score >= 80 ? "text-success border-success/40" : score >= 60 ? "text-warning border-warning/40" : "text-danger border-danger/40";
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-full border font-mono font-semibold",
        tone,
        size === "sm" ? "size-9 text-[11px]" : "size-12 text-sm",
      )}
    >
      {score}
    </span>
  );
}
