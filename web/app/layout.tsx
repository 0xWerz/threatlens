import type { Metadata } from "next";
import { Playfair_Display, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const displayFont = Playfair_Display({
    variable: "--font-display",
    subsets: ["latin"],
    weight: ["400", "700", "900"],
});

const monoFont = IBM_Plex_Mono({
    variable: "--font-mono",
    subsets: ["latin"],
    weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
    title: "ThreatLens — PR Security Guardrails",
    description:
        "Diff-first security scanning for pull requests. Catch hardcoded secrets, auth bypasses, and risky config changes before they merge.",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en">
            <body className={`${displayFont.variable} ${monoFont.variable}`}>
                {children}
            </body>
        </html>
    );
}
