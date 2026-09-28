import { FileX } from "lucide-react";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto flex max-w-[400px] flex-col items-center px-4 py-16 text-center">
      <FileX className="mb-3 size-6 text-fg-faint" />
      <h1 className="text-h3 font-semibold">This page doesn&apos;t exist</h1>
      <p className="mt-1 text-fg-muted">The research may have been archived or the link is wrong.</p>
      <Link href="/research" className="mt-4 inline-flex h-10 items-center rounded-sm bg-[var(--btn-primary)] px-[18px] font-semibold text-white hover:bg-[var(--btn-primary-hover)]">Go to Research</Link>
    </div>
  );
}
