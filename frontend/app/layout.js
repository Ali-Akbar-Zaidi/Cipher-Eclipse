import "./globals.css";

export const metadata = {
  title: "Cipher Eclipse",
  description: "Passive attack surface mapping and exploit-aware risk prioritisation",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
