import { NextResponse, type NextRequest } from 'next/server';

/** Adds the operator token to proxied /admin and /control calls server-side; the browser never holds it. */
export function proxy(req: NextRequest) {
  const headers = new Headers(req.headers);
  headers.delete('authorization'); // never forward a browser-supplied credential
  const token = process.env.WARDEN_ADMIN_TOKEN;
  if (token) headers.set('authorization', `Bearer ${token}`);
  return NextResponse.next({ request: { headers } });
}

export const config = { matcher: ['/admin/:path*', '/control/:path*'] };
