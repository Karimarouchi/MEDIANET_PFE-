const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function (app) {
  // SSE endpoints need special handling — disable buffering
  app.use(
    '/api/scans/*/logs',
    createProxyMiddleware({
      target: 'http://localhost:8080',
      changeOrigin: true,
      headers: {
        Connection: 'keep-alive',
      },
      onProxyRes: function (proxyRes) {
        // Disable buffering for SSE
        proxyRes.headers['X-Accel-Buffering'] = 'no';
        proxyRes.headers['Cache-Control'] = 'no-cache';
      },
    })
  );

  // All other API calls
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'http://localhost:8080',
      changeOrigin: true,
    })
  );
};
