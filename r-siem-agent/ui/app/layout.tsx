import "./globals.css";
import type { Metadata } from "next";
import { AppShell } from "@/components/app-shell";
import { Suspense, type ReactNode } from "react";

export const metadata: Metadata = {
  title: "R-SIEM SOC UI",
  description: "FR-06 SOC web UI for R-SIEM"
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<body>
				<Suspense fallback={<div className="p-8 text-sm text-ink-200">Loading UI shell...</div>}>
					<AppShell>{children}</AppShell>
				</Suspense>
			</body>
		</html>
	);
}
