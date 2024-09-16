// import type { Metadata } from "next";
// import localFont from "next/font/local";
// import "./globals.css";


// const geistSans = localFont({
//   src: "./fonts/GeistVF.woff",
//   variable: "--font-geist-sans",
//   weight: "100 900",
// });
// const geistMono = localFont({
//   src: "./fonts/GeistMonoVF.woff",
//   variable: "--font-geist-mono",
//   weight: "100 900",
// });

// export const metadata: Metadata = {
//   title: "Focusly.ai",
//   description: "Focusly seamlessly organizes your tasks and predicts what's next using AI.",
// };

// export default function RootLayout({
//   children,
// }: Readonly<{
//   children: React.ReactNode;
// }>) {
//   return (
//     <html lang="en">
//       <body
//         className={`${geistSans.variable} ${geistMono.variable} antialiased`}
//       >
//         {children}
//       </body>
//     </html>
//   );
// }

import type { Metadata } from "next";
import { Noto_Sans_Georgian } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const defaultFont = Noto_Sans_Georgian({ subsets: ["latin"] });

const ORIGIN_URL =
  process.env.NODE === "production"
    ? "https://focusly.com"
    : "http://localhost:3000";

export const metadata: Metadata = {
  title: "Focusly.ai",
  description:
    "Focusly seamlessly organizes your tasks and predicts what's nextusing AI.",
  icons: {
    icon: "/favicon.ico",
  },
  metadataBase: new URL(ORIGIN_URL),
  alternates: {
    canonical: ORIGIN_URL,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={defaultFont.className}>
        {children}
        <Toaster />
      </body>
    </html>
  );
 }
