export const environment = {
  production: true,
  siteUrl: 'https://koopa0.dev',
  siteName: 'koopa0.dev',
  // Absolute, same-origin base. The HTTP transfer cache keys on the request
  // URL, so the browser origin must be absolute to be matched against the SSR
  // origin (ssrApiUrl) through HTTP_TRANSFER_CACHE_ORIGIN_MAP. Requests reach
  // the Node server's /api proxy, which forwards them to the backend.
  apiUrl: 'https://koopa0.dev',
  ssrApiUrl: 'http://backend:8080',
};
