<?php

namespace App\Services\Fraud;

use App\Models\FraudEvent;
use Carbon\Carbon;
use App\Models\UserDevice;
use App\Models\FraudFlag;

class RulesEngine
{
    // Tune these for demo
    private int $windowMinutes = 5;
    private int $maxFailedAttempts = 5;
    private int $ipHopThreshold = 2;

    public function evaluateLoginAttempt(array $event): array
    {
        $identifier = $event['identifier'] ?? null;
        $deviceId = $event['device_id'] ?? null;
        $mfaVerified = (bool)($event['mfa_verified'] ?? false);
        $userId = $event['user_id'] ?? null;
        $ip = $event['ip'] ?? null;

        // Active BLOCK check (temporary lockout)
        $activeBlock = FraudFlag::query()
            ->where('decision', 'BLOCK')
            ->whereNotNull('expires_at')
            ->where('expires_at', '>', now())
            ->when($userId, fn($q) => $q->where('user_id', $userId))
            ->when(!$userId && $identifier, fn($q) => $q->where('identifier', $identifier))
            ->orderByDesc('id')
            ->first();

        if ($activeBlock) {
            return [
                'decision' => 'BLOCK',
                'risk_score' => (int) $activeBlock->risk_score,
                'triggered_rules' => json_decode($activeBlock->triggered_rules ?? '[]', true) ?: [],
                'reason_summary' => $activeBlock->reason_summary ?? 'ACTIVE_BLOCK',
                'expires_in' => now()->diffInSeconds($activeBlock->expires_at),
            ];
        }


        $now = Carbon::parse($event['occurred_at'] ?? now());
        $windowStart = $now->copy()->subMinutes($this->windowMinutes);

        // Query basis: prefer user_id, fallback identifier
        $eventId = $event['id'] ?? null;

        $q = FraudEvent::query()
            ->where('event_type', 'login_attempt')
            ->where('occurred_at', '>=', $windowStart);

        if ($userId) $q->where('user_id', $userId);
        elseif ($identifier) $q->where('identifier', $identifier);

        $eventId = $event['id'] ?? null;
        if ($eventId) {
            $q->where('id', '!=', $eventId);
        }

        $recent = $q->get();

        $triggered = [];
        $risk = 0;

        // R2: brute-ish attempts (failed attempts in window)
        $failedCount = $recent->where('success', false)->count() + (($event['success'] ?? false) ? 0 : 1);
        if ($failedCount >= $this->maxFailedAttempts) {
            $triggered[] = [
                'code' => 'R2_FAILED_BURST',
                'detail' => "Failed attempts in {$this->windowMinutes}m: {$failedCount}",
            ];
            $risk += 60;
        }

        // R2B: Failed burst => BLOCK
        $failedThreshold = 5;
        $blockMinutes = 10;

        $failedCount = $recent
            ->where('success', 0)
            ->count();

        if ($failedCount >= $failedThreshold) {
            $triggered[] = [
                'code' => 'R2B_FAILED_BURST_BLOCK',
                'detail' => "Failed logins in 5m: {$failedCount} (threshold {$failedThreshold})",
            ];

            return [
                'decision' => 'BLOCK',
                'risk_score' => 100,
                'triggered_rules' => $triggered,
                'reason_summary' => 'R2B_FAILED_BURST_BLOCK',
                'expires_at' => now()->addMinutes($blockMinutes),
            ];
        }


        // R1: IP hopping burst (distinct IPs in window)
        $ips = $recent->pluck('ip')->filter()->unique()->values()->all();
        if ($ip) $ips = array_values(array_unique(array_merge($ips, [$ip])));
        if (count($ips) >= $this->ipHopThreshold) {
            $triggered[] = [
                'code' => 'R1_IP_HOP',
                'detail' => "Distinct IPs in {$this->windowMinutes}m: " . count($ips),
                'ips' => $ips,
            ];
            $risk += 50;
        }

        // R3: geo anomaly (only if we have lat/lon now and last known)
        // Minimal: if previous event had lat/lon and current has lat/lon and distance implies > 900 km/h => flag
        $geoTriggered = $this->geoAnomaly($recent, $event);
        if ($geoTriggered) {
            $triggered[] = $geoTriggered;
            $risk += 60;
        }

        // R3B: Geo anomaly cooldown (if impossible travel happened recently, keep step-up for a window)
        $cooldownMinutes = 10;
        $recentGeoFlags = FraudFlag::query()
            ->where('user_id', $userId)
            ->where('created_at', '>=', now()->subMinutes($cooldownMinutes))
            ->get();

        $hadRecentGeoAnomaly = false;

        foreach ($recentGeoFlags as $f) {
            if (!$f->triggered_rules) continue;

            $rules = is_string($f->triggered_rules) ? json_decode($f->triggered_rules, true) : $f->triggered_rules;
            if (!is_array($rules)) continue;

            foreach ($rules as $r) {
                if (($r['code'] ?? null) === 'R3_GEO_ANOMALY') {
                    $hadRecentGeoAnomaly = true;
                    break 2;
                }
            }
        }

        if (!$mfaVerified && $userId && $hadRecentGeoAnomaly) {
            $triggered[] = [
                'code' => 'R3B_GEO_COOLDOWN',
                'detail' => "Geo anomaly cooldown active ({$cooldownMinutes}m)",
            ];
            $risk = max($risk, 60); // force STEP_UP
        }


        // R4: unfamiliar device (requires user_id + device_id) => step-up
        if (!$mfaVerified && $userId && $deviceId) {
            $known = UserDevice::query()
                ->where('user_id', $userId)
                ->where('device_id', $deviceId)
                ->exists();

            if (!$known) {
                $triggered[] = [
                    'code' => 'R4_NEW_DEVICE',
                    'detail' => "Unfamiliar device_id for user",
                ];
                $risk += 55; // ensures STEP_UP threshold (>=50)
            }
        }

        // Decision
        $decision = 'ALLOW';
        if ($risk >= 80) $decision = 'BLOCK';
        elseif ($risk >= 50) $decision = 'STEP_UP';

        return [
            'decision' => $decision,
            'risk_score' => $risk,
            'triggered_rules' => $triggered,
            'reason_summary' => $triggered[0]['code'] ?? null,
        ];
    }

    private function geoAnomaly($recent, array $event): ?array
    {
        $lat = $event['lat'] ?? null;
        $lon = $event['lon'] ?? null;
        $occurredAt = Carbon::parse($event['occurred_at'] ?? now());

        if ($lat === null || $lon === null) {
            return null; // no geo data => no geo rule
        }

        $last = $recent
            ->whereNotNull('lat')
            ->whereNotNull('lon')
            ->sortByDesc('occurred_at')
            ->first();

        if (!$last) return null;

        $hours = max(0.01, $occurredAt->diffInSeconds(Carbon::parse($last->occurred_at)) / 3600.0);
        $km = $this->haversineKm((float)$last->lat, (float)$last->lon, (float)$lat, (float)$lon);
        $speed = $km / $hours;

        if ($speed > 900) {
            return [
                'code' => 'R3_GEO_ANOMALY',
                'detail' => sprintf("Impossible travel: %.0f km in %.2f h (%.0f km/h)", $km, $hours, $speed),
            ];
        }

        return null;
    }

    private function haversineKm(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $R = 6371.0;
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);

        $a = sin($dLat/2) ** 2
           + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon/2) ** 2;

        $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
        return $R * $c;
    }
}
