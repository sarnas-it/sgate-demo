import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Sarnas Security Gate — демо",
  description: "Демонстрационный стенд Security Gate: SCA, секреты, SAST, контейнеры",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="ru">
      <body
        style={{
          margin: 0,
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
          background: "#0b1020",
          color: "#e8ecf8",
        }}
      >
        {children}
      </body>
    </html>
  );
}
