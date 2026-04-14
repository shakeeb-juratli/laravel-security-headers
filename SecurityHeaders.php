<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    
	
	
    public function handle(Request $request, Closure $next): Response
    {
        // ─────────────────────────────────────────────
        //  HTTPS erzwingen (Production + Proxy Support)
       
        if (app()->environment('production')) {
            $isSecure = $request->secure() || $request->header('X-Forwarded-Proto') === 'https';
            if (!$isSecure) {
                $timestamp = now()->format('d.m.Y H:i:s');
                Log::warning("[SecurityHeaders] HTTP-Zugriff blockiert — IP: {$request->ip()} — {$timestamp}");
                abort(403, "HTTPS erforderlich. Zeitpunkt: {$timestamp}");
            }
        }

        // ─────────────────────────────────────────────
        //  Nonce generieren (für CSP)
        
        $nonce = base64_encode(random_bytes(16));
        app()->instance('csp-nonce', $nonce);

        $response = $next($request);

        // ─────────────────────────────────────────────
        //  Timestamp + URL erfassen & loggen
        
        $timestamp = now()->format('d.m.Y H:i:s');
        $url       = $request->fullUrl();
        $method    = $request->method();
        $ip        = $request->ip();
        $userAgent = $request->userAgent();
        $status    = $response->getStatusCode();

        // URL + Zeitstempel im Response-Header
        $response->headers->set('X-Response-Time', $timestamp);
        $response->headers->set('X-Request-URL', $url);

        // Logging in Laravel Log (400+ als Warning, sonst Info)
        if ($status >= 400) {
            Log::warning("[SecurityHeaders] {$method} {$url} | Status: {$status} | IP: {$ip} | {$timestamp} | UA: {$userAgent}");
        } else {
            Log::info("[SecurityHeaders] {$method} {$url} | Status: {$status} | IP: {$ip} | {$timestamp} | UA: {$userAgent}");
        }

        // ─────────────────────────────────────────────
        //  Content-Security-Policy (Ultra-Level)
        
        $csp = implode(' ', [
            "default-src 'none';",
            "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic';",
            "style-src 'self' 'nonce-{$nonce}';",
            "img-src 'self' data: blob:;",
            "font-src 'self';",
            "connect-src 'self';",
            "frame-ancestors 'none';",
            "form-action 'self';",
            "base-uri 'none';",
            "object-src 'none';",
            "upgrade-insecure-requests;",
            "require-trusted-types-for 'script';",
            "report-to csp-endpoint;",
        ]);

        // Im Local-Modus nur Report-Only (kein Blockieren)
        if (app()->environment('local')) {
            $response->headers->set('Content-Security-Policy-Report-Only', $csp);
        } else {
            $response->headers->set('Content-Security-Policy', $csp);
        }

        // ─────────────────────────────────────────────
        //  Reporting API (CSP-Verstösse melden)
        
        $response->headers->set('Report-To', json_encode([
            "group"     => "csp-endpoint",
            "max_age"   => 10886400,
            "endpoints" => [
                ["url" => url('/csp-report')]
            ]
        ]));

        // ─────────────────────────────────────────────
        //  Standard Security Header
         

        // Verhindert Clickjacking
        $response->headers->set('X-Frame-Options', 'DENY');

        // Verhindert XSS-Angriffe im Browser
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        // Verhindert MIME-Sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Schützt die Privatsphäre bei Weiterleitungen
        $response->headers->set('Referrer-Policy', 'no-referrer');

        // Schränkt den Zugriff auf sensible Browser-APIs ein
        $response->headers->set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

        // ─────────────────────────────────────────────
        //  Erweiterte Isolation Header
        

        // Blockiert Adobe Flash/PDF Cross-Domain-Zugriffe
        $response->headers->set('X-Permitted-Cross-Domain-Policies', 'none');

        // Schützt vor Spectre-Angriffen
        $response->headers->set('Cross-Origin-Embedder-Policy', 'require-corp');

        // Isoliert den Browser-Kontext
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');

        // Verhindert das Einbinden der Ressourcen von fremden Seiten
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        // ─────────────────────────────────────────────
        //  HSTS – nur bei aktiver HTTPS-Verbindung
        
        if ($request->secure() || $request->header('X-Forwarded-Proto') === 'https') {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=63072000; includeSubDomains; preload'
            );
        }

        return $response;
    }
}
