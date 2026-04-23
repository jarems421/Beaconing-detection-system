import "./globals.css";

export const metadata = {
  title: "Beacon Ops Demo",
  description:
    "Operational beaconing detection app demo for hybrid rules and Random Forest scoring.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
