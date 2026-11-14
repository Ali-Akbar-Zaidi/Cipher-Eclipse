// PLACEHOLDER: Shuja replaces this app with the real dashboard.
// Kept only so `docker compose up` works before the real frontend lands.
export const metadata = { title: "Cipher Eclipse" };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: "2rem" }}>{children}</body>
    </html>
  );
}
