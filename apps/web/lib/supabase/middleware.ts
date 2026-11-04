import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function updateSession(request: NextRequest) {
  let response = NextResponse.next({
    request: {
      headers: request.headers,
    },
  });

  const supabaseUrl =
    process.env.NEXT_PUBLIC_SUPABASE_URL || "https://placeholder-project.supabase.co";
  const supabaseKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    "placeholder-publishable-key";

  const isConfigured =
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
    !process.env.NEXT_PUBLIC_SUPABASE_URL.includes("placeholder") &&
    (process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

  const supabase = createServerClient(supabaseUrl, supabaseKey, {
    cookies: {
      get(name: string) {
        return request.cookies.get(name)?.value;
      },
      set(name: string, value: string, options: CookieOptions) {
        request.cookies.set({
          name,
          value,
          ...options,
        });
        response = NextResponse.next({
          request: {
            headers: request.headers,
          },
        });
        response.cookies.set({
          name,
          value,
          ...options,
        });
      },
      remove(name: string, options: CookieOptions) {
        request.cookies.set({
          name,
          value: "",
          ...options,
        });
        response = NextResponse.next({
          request: {
            headers: request.headers,
          },
        });
        response.cookies.set({
          name,
          value: "",
          ...options,
        });
      },
    },
  });

  let user = null;
  if (isConfigured) {
    try {
      const {
        data: { user: authUser },
      } = await supabase.auth.getUser();
      user = authUser;
    } catch {
      user = null;
    }
  }

  const { pathname } = request.nextUrl;
  const isAuthRoute =
    pathname.startsWith("/login") ||
    pathname.startsWith("/signup") ||
    pathname.startsWith("/register") ||
    pathname.startsWith("/forgot-password") ||
    pathname.startsWith("/auth/callback");

  const isStaticOrAsset =
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api") ||
    pathname.includes(".") ||
    pathname === "/favicon.ico";

  // If live credentials are configured, enforce strict protection
  if (isConfigured && !isStaticOrAsset) {
    if (!user && !isAuthRoute) {
      const url = request.nextUrl.clone();
      url.pathname = "/login";
      url.searchParams.set("redirectTo", pathname);
      return NextResponse.redirect(url);
    }

    if (user && isAuthRoute && !pathname.startsWith("/auth/callback")) {
      const url = request.nextUrl.clone();
      url.pathname = "/";
      return NextResponse.redirect(url);
    }
  }

  return response;
}
