# 🛡️ Laravel Security Headers Middleware

A production-ready Laravel 11/12 middleware that adds comprehensive HTTP security headers to protect your web application against common attacks.

---

##  Features

- ✅ HTTPS enforcement with reverse proxy support
- ✅ Ultra-level Content Security Policy (CSP) with Nonce
- ✅ CSP Report-Only mode in local environment
- ✅ HSTS (HTTP Strict Transport Security) — 2 years
- ✅ Clickjacking protection
- ✅ XSS protection
- ✅ MIME-Sniffing prevention
- ✅ Cross-Origin isolation headers
- ✅ Privacy protection via Referrer-Policy
- ✅ Browser API restrictions (Geolocation, Microphone, Camera)
- ✅ Request logging with URL, IP, Status, User-Agent & Timestamp
- ✅ Laravel 11 & 12 compatible (no Kernel.php)

---

##  Installation

### 1. Middleware kopieren

Datei in dein Laravel-Projekt kopieren:

```
app/Http/Middleware/SecurityHeaders.php
```

### 2. Middleware registrieren

In `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
})
```

### 3. CSP-Nonce in Blade-Templates verwenden

```html
<script nonce="{{ app('csp-nonce') }}">
    // dein JavaScript
</script>

<style nonce="{{ app('csp-nonce') }}">
    /* dein CSS */
</style>
```

### 4. CSP-Report Route anlegen (optional)

In `routes/web.php`:

```php
use Illuminate\Http\Request;

Route::post('/csp-report', function (Request $request) {
    \Illuminate\Support\Facades\Log::warning('[CSP-Report] ' . $request->getContent());
    return response()->noContent();
})->withoutMiddleware([\App\Http\Middleware\SecurityHeaders::class]);
```

---

##  Security Headers Overview

| Header | Wert | Schutz gegen |
|--------|------|--------------|
| `Content-Security-Policy` | Nonce-based, Ultra-Level | XSS, Dateninjektionen |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | MITM, SSL-Stripping |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Reflected XSS |
| `X-Content-Type-Options` | `nosniff` | MIME-Sniffing |
| `Referrer-Policy` | `no-referrer` | Datenlecks via URL |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Gefährliche Browser-APIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Spectre-Angriffe |
| `Cross-Origin-Opener-Policy` | `same-origin` | Cross-Origin Isolation |
| `Cross-Origin-Resource-Policy` | `same-origin` | Ressourcen-Einbindung |
| `X-Permitted-Cross-Domain-Policies` | `none` | Flash/PDF Cross-Domain |

---

##  Logging

Jeder Request wird in `storage/logs/laravel.log` geloggt:

```
// Normaler Request (Info)
[SecurityHeaders] GET https://example.com/dashboard | Status: 200 | IP: 192.168.1.1 | 14.04.2026 15:32:10 | UA: Mozilla/5.0...

// Fehler-Request (Warning)
[SecurityHeaders] GET https://example.com/admin | Status: 403 | IP: 192.168.1.1 | 14.04.2026 15:32:10 | UA: curl/7.68.0

// HTTP-Zugriff blockiert (Warning)
[SecurityHeaders] HTTP-Zugriff blockiert — IP: 192.168.1.1 — 14.04.2026 15:32:10
```

---

##  Environment-Verhalten

| Feature | `local` | `production` |
|---------|---------|--------------|
| HTTPS erzwingen | ❌ | ✅ |
| CSP aktiv | Report-Only | Enforced |
| HSTS | ❌ | ✅ |
| Logging | ✅ | ✅ |

---

##  Requirements

- PHP `>= 8.2`
- Laravel `11.x` or `12.x`

---

##  License

MIT License — free to use, modify and distribute.
