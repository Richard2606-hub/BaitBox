/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const defaultBackend = process.env.VERCEL
      ? "https://lights-halo-scan-celtic.trycloudflare.com"
      : "http://127.0.0.1:8000";
    const backendUrl = (
      process.env.BACKEND_URL ||
      process.env.NEXT_PUBLIC_API_BASE_URL ||
      defaultBackend
    ).replace(/\/+$/, "");
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
      {
        source: "/screenshots/:path*",
        destination: `${backendUrl}/screenshots/:path*`,
      },
      {
        source: "/trap/:path*",
        destination: `${backendUrl}/trap/:path*`,
      },
    ];
  },
};

export default nextConfig;
