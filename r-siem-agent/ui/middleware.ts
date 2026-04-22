import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (pathname === "/honeypot" || pathname === "/infrastructure" || pathname.startsWith("/infrastructure/")) {
    return NextResponse.redirect(new URL("/", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/honeypot", "/infrastructure/:path*"]
};
