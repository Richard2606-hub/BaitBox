/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const backendUrl = (
      process.env.BACKEND_URL ||
      process.env.NEXT_PUBLIC_API_BASE_URL ||
      "http://localhost:8000"
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
