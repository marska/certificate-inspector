import type { Metadata, Viewport } from 'next';
import Script from 'next/script';

import './globals.css';

export const metadata: Metadata = {
  title: 'Certificate Inspector — decode X.509 certificates in your browser',
  description:
    'Paste a certificate, a Base64 blob or a whole chain and see every X.509 property. ' +
    'Everything is parsed locally in your browser — nothing is uploaded.',
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#fbfbfc' },
    { media: '(prefers-color-scheme: dark)', color: '#0a0a0c' },
  ],
};

/**
 * Applies the stored theme before first paint. Inline because anything async
 * would flash the wrong colours.
 */
const themeScript = `
(function () {
  try {
    var stored = localStorage.getItem('ci-theme');
    var dark = stored ? stored === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (dark) document.documentElement.classList.add('dark');
  } catch (e) {}
})();
`;

// Typed explicitly rather than with Next's generated `LayoutProps<'/'>`: that
// global only exists after a build has run, which would make `npm run typecheck`
// fail on a fresh checkout — exactly what CI does.
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <body className="flex min-h-full flex-col">
        <Script
          id="theme-init"
          strategy="beforeInteractive"
          dangerouslySetInnerHTML={{ __html: themeScript }}
        />
        {children}
      </body>
    </html>
  );
}
