import type { Metadata } from "next";
import { Suspense } from "react";
import "./globals.css";
import { AppProvider } from "@/components/providers";
import { AppShell } from "@/components/shell/app-shell";
import { ToastProvider } from "@/components/ui/feedback";

export const metadata: Metadata = {
  title: { default: "ThreatLens", template: "%s · ThreatLens" },
  description: "Autonomous threat research workbench",
};

// Apply the saved theme before first paint to avoid a flash.
const themeScript = `(function(){try{var t=localStorage.getItem('tl.theme')||'light';var d=t==='dark'||(t==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light'}catch(e){}})()`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <ToastProvider>
          <Suspense>
            <AppProvider>
              <AppShell>{children}</AppShell>
            </AppProvider>
          </Suspense>
        </ToastProvider>
      </body>
    </html>
  );
}
