# FreeLLMAPI Reverse Proxy & CORS Guide

FreeLLMAPI (`github.com/tashfeenahmed/freellmapi`) provides a unified OpenAI-compatible `/v1` endpoint (default: `http://localhost:3001/v1`).

When using FreeLLMAPI from SecureLoop AI:

- The user's API key is kept exclusively in browser `sessionStorage`.
- The key is sent **directly and only** from your browser to your FreeLLMAPI endpoint URL.
- Keys are never routed through our backend, database, or third-party servers.

---

## 1. Running SecureLoop AI Locally (Recommended)

When you run SecureLoop AI locally via `npm run dev`:

- The app runs on `http://localhost:5173`.
- Both the app and your FreeLLMAPI instance run on `http://localhost:*`.
- Browser mixed-content restrictions **do not apply** on `http://`.
- A built-in Vite dev-server proxy is configured at `/freellm`:
  - Target: `http://localhost:3001`
  - Any request to `/freellm/v1/*` routes transparently to `http://localhost:3001/v1/*` without cross-origin preflight issues.

---

## 2. Using FreeLLMAPI with the Deployed App (HTTPS)

Modern web browsers enforce two security constraints when a web application is served over HTTPS (such as `https://*.lovable.app`):

1. **Mixed Content**: HTTPS pages cannot make plain `http://` network requests to private or loopback addresses (`http://localhost:3001`).
2. **Local Network Access (Private Network Access - W3C / Chrome 94+)**: Browsers restrict public HTTPS origins from initiating requests to private network addresses unless the local server responds with HTTPS and specific headers (`Access-Control-Allow-Private-Network: true`).

To use your local FreeLLMAPI instance with the deployed HTTPS site without routing your API keys through any third party, use a local reverse proxy that terminates TLS and provides CORS headers.

### Caddy Reverse Proxy Configuration

[Caddy](https://caddyserver.com/) provides automatic local HTTPS certificates. Create a `Caddyfile`:

```caddy
# Replace with your local domain or localhost with HTTPS
https://localhost:8443 {
    # TLS with Caddy's internal local CA
    tls internal

    # Handle OPTIONS preflight requests
    @options {
        method OPTIONS
    }
    handle @options {
        header Access-Control-Allow-Origin "https://your-secureloop-app.lovable.app"
        header Access-Control-Allow-Methods "GET, POST, OPTIONS"
        header Access-Control-Allow-Headers "Authorization, Content-Type"
        header Access-Control-Allow-Private-Network "true"
        header Access-Control-Max-Age "86400"
        respond 204
    }

    # Proxy /v1/* to FreeLLMAPI
    handle /v1/* {
        header Access-Control-Allow-Origin "https://your-secureloop-app.lovable.app"
        header Access-Control-Allow-Private-Network "true"
        reverse_proxy localhost:3001
    }
}
```

Run Caddy:

```bash
caddy run
```

Then in SecureLoop AI's **Endpoint Base URL** field, enter:

```
https://localhost:8443/v1
```

### Tradeoff Summary

| Setup                                 | Mixed Content         | CORS / LNA                         | Setup Complexity         | Privacy / Key Security                                          |
| ------------------------------------- | --------------------- | ---------------------------------- | ------------------------ | --------------------------------------------------------------- |
| **Local Dev (`npm run dev`)**         | None (both HTTP)      | Handled by Vite proxy              | Minimal (`npm run dev`)  | 100% in browser                                                 |
| **Local Caddy TLS Proxy**             | None (HTTPS to HTTPS) | Handled by Caddy headers           | Requires Caddy installed | 100% in browser                                                 |
| **Cloud Tunnel (Cloudflare / ngrok)** | None (HTTPS tunnel)   | Requires tunnel CORS configuration | Requires tunnel account  | 100% in browser                                                 |
| **Server Relay (Forbidden)**          | None                  | Bypasses browser restrictions      | Minimal for user         | ❌ Violates privacy constraint (keys touch intermediate server) |
