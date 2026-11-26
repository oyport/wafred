import { apiClient } from './client'
import type {
  ErrorPage,
  ErrorPageContentType,
  ErrorPageScope,
  Page,
  UpsertErrorPageRequest,
} from './types'

/**
 * Custom pages — `/api/v1/error-pages` (administrators only).
 *
 * One global template per status code: the list applies to every site, so the
 * settings page is the only place to edit it. The template is rendered with a
 * small set of variables (see {@link ERROR_PAGE_VARIABLES}) before being
 * returned to the client, so operators can brand 403/429/5xx responses.
 */
export const errorPagesApi = {
  list: (scope?: ErrorPageScope) =>
    apiClient.get<Page<ErrorPage>>('/error-pages', {
      query: scope ? { scope } : undefined,
    }),

  upsert: (data: UpsertErrorPageRequest) =>
    apiClient.post<ErrorPage>('/error-pages', data),

  update: (id: string, data: Partial<UpsertErrorPageRequest>) =>
    apiClient.put<ErrorPage>(`/error-pages/${id}`, data),

  delete: (id: string) => apiClient.delete<void>(`/error-pages/${id}`),
}

/** Variables the template engine substitutes. Rendered in the editor sidebar. */
export const ERROR_PAGE_VARIABLES = [
  { name: 'error_code', description: 'The HTTP status code, e.g. 403' },
  { name: 'error_message', description: 'Human-readable reason phrase' },
  { name: 'request_id', description: 'Unique id for correlating with logs' },
  { name: 'request_path', description: 'The requested URI path' },
  { name: 'request_host', description: 'The Host header of the request' },
  { name: 'client_ip', description: 'The caller IP address' },
  { name: 'timestamp', description: 'ISO-8601 time the error occurred' },
  { name: 'site_name', description: 'The configured site name' },
  {
    name: 'upstream_name',
    description:
      'Upstream group that was tried (gateway 502/503/504 pages; empty on other errors)',
  },
  {
    name: 'upstream_addr',
    description:
      'Backend address that was tried, e.g. 10.0.0.9:8080 (empty on non-upstream errors)',
  },
] as const
/** Variables available only to the challenge-page template. */
export const CHALLENGE_PAGE_VARIABLES = [
  {
    name: 'challenge_scripts',
    description:
      'Compiled fingerprint, proof-of-work, verification and redirect scripts. Always use it as {{ challenge_scripts | safe }}.',
  },
  { name: 'brand_name', description: 'Brand name (HTML-escaped by Tera)' },
  { name: 'request_id', description: 'Unique id for this challenge' },
  { name: 'difficulty', description: 'Proof-of-work difficulty in leading zero bits' },
  { name: 'verify_endpoint', description: 'Endpoint the page posts the solution to' },
  { name: 'original_url', description: 'URL to redirect to after verification' },
] as const


/** Sample values used by the live-preview iframe. */
export const ERROR_PAGE_SAMPLE: Record<string, string> = {
  error_code: '403',
  error_message: 'Forbidden',
  request_id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  request_path: '/admin/settings',
  request_host: 'example.com',
  client_ip: '203.0.113.44',
  /** Short alias for `request_host`; the gateway HTML-escapes it on
   * `unmatched_host` pages. Sampled as a bare-IP hit. */
  host: '203.0.113.10',
  timestamp: new Date().toISOString(),
  site_name: 'Example Site',
  upstream_name: '',
  upstream_addr: '',
}
/** Sample values for the challenge-page live preview. */
export const CHALLENGE_PAGE_SAMPLE: Record<string, string> = {
  ...ERROR_PAGE_SAMPLE,
  error_code: '503',
  error_message: 'Service Unavailable',
  brand_name: 'WAFred',
  request_id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  difficulty: '20',
  verify_endpoint: '/_pingwaf/challenge/verify',
  original_url: '/',
  challenge_scripts:
    '<script>/* compiled challenge scripts are injected here at runtime */</script>',
}


const HTML_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{error_code}} {{error_message}}</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f7f7f8; color: #1d1d1d;
    }
    .card { text-align: center; padding: 48px 32px; max-width: 480px; }
    .code {
      font-size: 96px; font-weight: 800; line-height: 1; letter-spacing: -4px;
      background: linear-gradient(135deg, #d8324f, #e54d2a);
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    h1 { font-size: 22px; margin: 16px 0 8px; }
    p { color: #666; font-size: 14px; line-height: 1.6; margin: 0; }
    .meta {
      margin-top: 24px; font-family: ui-monospace, Menlo, monospace;
      font-size: 11px; color: #999;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="code">{{error_code}}</div>
    <h1>{{error_message}}</h1>
    <p>Access to <strong>{{request_path}}</strong> on {{request_host}} was denied.</p>
    <div class="meta">Request ID: {{request_id}} &middot; {{timestamp}}</div>
  </div>
</body>
</html>`

const JSON_TEMPLATE = `{
  "error": {
    "code": {{error_code}},
    "message": "{{error_message}}",
    "request_id": "{{request_id}}",
    "path": "{{request_path}}",
    "timestamp": "{{timestamp}}"
  }
}`

const TEXT_TEMPLATE = `{{error_code}} {{error_message}}
Request {{request_id}} to {{request_path}} was rejected at {{timestamp}}.`

/** Gateway-class failures carry upstream context; the defaults for those
 * status codes show which upstream and backend were involved. */
const HTML_GATEWAY_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{error_code}} {{error_message}}</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f7f7f8; color: #1d1d1d;
    }
    .card { text-align: center; padding: 48px 32px; max-width: 480px; }
    .code {
      font-size: 96px; font-weight: 800; line-height: 1; letter-spacing: -4px;
      background: linear-gradient(135deg, #d8324f, #e54d2a);
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    h1 { font-size: 22px; margin: 16px 0 8px; }
    p { color: #666; font-size: 14px; line-height: 1.6; margin: 0; }
    .meta {
      margin-top: 24px; font-family: ui-monospace, Menlo, monospace;
      font-size: 11px; color: #999;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="code">{{error_code}}</div>
    <h1>{{error_message}}</h1>
    <p><strong>{{request_host}}</strong> could not reach its origin server{% if upstream_name %} via <strong>{{upstream_name}}</strong>{% endif %}. This is not a security block — please try again in a few moments.</p>
    {% if upstream_addr %}
    <p>Backend tried: <strong>{{upstream_addr}}</strong></p>
    {% endif %}
    <div class="meta">Request ID: {{request_id}} &middot; {{timestamp}}</div>
  </div>
</body>
</html>`

const JSON_GATEWAY_TEMPLATE = `{
  "error": {
    "code": {{error_code}},
    "message": "{{error_message}}",
    "request_id": "{{request_id}}",
    "path": "{{request_path}}",
    "timestamp": "{{timestamp}}",
    "upstream_name": "{{ upstream_name }}",
    "upstream_addr": "{{ upstream_addr }}"
  }
}`

const TEXT_GATEWAY_TEMPLATE = `{{error_code}} {{error_message}}
Request {{request_id}} to {{request_path}} could not reach the origin server.
Upstream: {{ upstream_name }} (tried {{ upstream_addr }})
Rejected at {{timestamp}}.`

/** Status codes whose default templates carry upstream context. */
const GATEWAY_STATUS_CODES = new Set([502, 503, 504])

/** The built-in template for a status code, used by "Reset to default". */
export function defaultErrorPageTemplate(
  statusCode: number,
  contentType: ErrorPageContentType = 'text/html',
): string {
  const gateway = GATEWAY_STATUS_CODES.has(statusCode)
  if (contentType === 'application/json') {
    return gateway ? JSON_GATEWAY_TEMPLATE : JSON_TEMPLATE
  }
  if (contentType === 'text/plain') {
    return gateway ? TEXT_GATEWAY_TEMPLATE : TEXT_TEMPLATE
  }
  return gateway ? HTML_GATEWAY_TEMPLATE : HTML_TEMPLATE
}

/**
 * The default challenge-page template. It is presentation only: the required
 * DOM ids are dereferenced by the compiled script, and the script itself is
 * injected at `{{ challenge_scripts | safe }}`.
 */
export function defaultChallengePageTemplate(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow" />
  <title>Checking your browser — {{ brand_name }}</title>
  <style>
    :root { color-scheme: light dark; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f8f9fa; color: #1a1a2e; }
    .card { text-align: center; padding: 48px 32px; max-width: 480px; }
    .brand { font-size: 18px; font-weight: 700; margin-bottom: 24px; }
    .countdown { font-size: 20px; font-weight: 700; color: #2563eb; }
    .spinner-wrap { margin: 24px auto; width: 64px; height: 64px; }
    .spinner { width: 64px; height: 64px; border-radius: 50%;
      border: 3px solid #e2e8f0; border-top-color: #2563eb;
      animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    h1 { font-size: 20px; margin: 12px 0; }
    .subtitle { color: #555; font-size: 14px; line-height: 1.6; }
    .status { display: none; margin-top: 20px; font-size: 13px; }
    .status.visible { display: block; }
    .progress-bar { display: none; height: 4px; background: #e2e8f0; margin-top: 16px; }
    .progress-bar.visible { display: block; }
    .progress-bar .fill { height: 100%; width: 0; background: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">{{ brand_name }}</div>
    <div class="spinner-wrap" id="spinnerWrap"><div class="spinner"></div></div>
    <div class="countdown" id="countdown">5</div>
    <h1 id="title">Checking your browser…</h1>
    <p class="subtitle" id="subtitle">Please wait while we verify your browser.</p>
    <div class="progress-bar" id="progressBar"><div class="fill" id="progressFill"></div></div>
    <div class="status" id="status"></div>
    <p class="subtitle">Ray ID: {{ request_id }}</p>
  </div>
  {{ challenge_scripts | safe }}
</body>
</html>`
}

/** Friendly reason phrases for the default status codes. */
export const ERROR_PAGE_MESSAGES: Record<number, string> = {
  404: 'Not Found',
  421: 'Misdirected Request',
  403: 'Forbidden',
  429: 'Too Many Requests',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
}

/**
 * Renders a template against sample data for the live-preview iframe.
 * Unknown variables are left intact so authors can see what did not resolve.
 */
export function renderErrorPageTemplate(
  template: string,
  sample: Record<string, string> = ERROR_PAGE_SAMPLE,
): string {
  return template.replace(
    /\{\{\s*(\w+)(?:\s*\|\s*safe)?\s*\}\}/g,
    (match, key: string) => (key in sample ? sample[key] : match),
  )
}

/** Render the editor preview using the selected response status and scope. */
export function renderErrorPagePreview(
  template: string,
  statusCode: number,
  scope: 'site' | 'unmatched_host' | 'challenge' = 'site',
): string {
  const base = scope === 'challenge' ? CHALLENGE_PAGE_SAMPLE : ERROR_PAGE_SAMPLE
  return renderErrorPageTemplate(template, {
    ...base,
    error_code: String(statusCode),
    error_message: ERROR_PAGE_MESSAGES[statusCode] ?? String(statusCode),
  })
}

export const errorPageKeys = {
  all: ['error-pages'] as const,
  list: (scope?: ErrorPageScope) => ['error-pages', 'list', scope ?? 'all'] as const,
}

export default errorPagesApi
