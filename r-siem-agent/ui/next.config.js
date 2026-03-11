/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  distDir: process.env.RSIEM_UI_DIST_DIR || ".next"
};

module.exports = nextConfig;
