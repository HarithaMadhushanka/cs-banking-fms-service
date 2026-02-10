<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\FraudEvent;
use App\Models\FraudFlag;
use App\Models\UserDevice;
use App\Services\Fraud\RulesEngine;
use Illuminate\Http\Request;

class LoginAttemptController extends Controller
{
    public function store(Request $request, RulesEngine $engine)
    {
        $data = $request->validate([
            'correlation_id' => 'nullable|string|max:64',
            'user_id' => 'nullable|integer',
            'identifier' => 'nullable|string|max:191',
            'device_id' => 'nullable|string|max:128',
            'mfa_verified' => 'nullable|boolean',
            'ip' => 'nullable|string|max:64',
            'user_agent' => 'nullable|string',
            'success' => 'required|boolean',
            'country' => 'nullable|string|max:2',
            'city' => 'nullable|string|max:128',
            'lat' => 'nullable|numeric',
            'lon' => 'nullable|numeric',
            'occurred_at' => 'nullable|date',
        ]);

        $data['event_type'] = 'login_attempt';
        $data['occurred_at'] = $data['occurred_at'] ?? now();

        $identifier = $data['identifier'] ?? null;
        $userId = $data['user_id'] ?? null;
        $deviceId = $data['device_id'] ?? null;

        /**
         * 0) Active BLOCK short-circuit MUST be first.
         * If blocked, return BLOCK and do not run RulesEngine.
         * We still store an event for audit.
         */
        $hasKey = !empty($userId) || !empty($identifier);
        if ($hasKey) {
            $activeBlock = FraudFlag::query()
                ->where('decision', 'BLOCK')
                ->whereNotNull('expires_at')
                ->where('expires_at', '>', now())
                ->where(function ($q) use ($userId, $identifier) {
                    if (!empty($userId)) {
                        $q->where('user_id', $userId);
                        if (!empty($identifier)) $q->orWhere('identifier', $identifier);
                    } else {
                        $q->where('identifier', $identifier);
                    }
                })
                ->orderByDesc('id')
                ->first();

            if ($activeBlock) {
                // store event for audit trail
                $blockedEvent = $data;
                $blockedEvent['success'] = false;
                $event = FraudEvent::create($blockedEvent);

                $rules = $activeBlock->triggered_rules;
                if (is_string($rules)) $rules = json_decode($rules, true) ?: [];

                return response()->json([
                    'stored_event_id' => $event->id,
                    'decision' => 'BLOCK',
                    'risk_score' => (int) $activeBlock->risk_score,
                    'triggered_rules' => $rules,
                    'flag_id' => $activeBlock->id,
                    'expires_in' => now()->diffInSeconds($activeBlock->expires_at),
                ]);
            }
        }

        /**
         * R5) Missing device_id -> BLOCK (explicit 5th rule).
         * Deterministic, demo-friendly, and prevents automation/replay attempts.
         */
        if (empty($deviceId)) {
            // store event for audit
            $event = FraudEvent::create($data);

            $triggeredRules = [
                ['code' => 'R5_MISSING_DEVICE_ID', 'detail' => 'device_id not provided'],
            ];

            $flag = FraudFlag::create([
                'correlation_id' => $data['correlation_id'] ?? null,
                'user_id' => $userId,
                'identifier' => $identifier,
                'decision' => 'BLOCK',
                'risk_score' => 100,
                'reason_summary' => 'R5_MISSING_DEVICE_ID',
                'triggered_rules' => $triggeredRules,
                'expires_at' => now()->addMinutes(10),
            ]);

            return response()->json([
                'stored_event_id' => $event->id,
                'decision' => 'BLOCK',
                'risk_score' => 100,
                'triggered_rules' => $triggeredRules,
                'flag_id' => $flag->id,
                'expires_in' => now()->diffInSeconds($flag->expires_at),
            ]);
        }

        // 1) store raw event
        $event = FraudEvent::create($data);

        // 2) evaluate RulesEngine rules (R1/R2/R3/etc.)
        $result = $engine->evaluateLoginAttempt($event->toArray());

        $decision = $result['decision'] ?? 'ALLOW';
        $riskScore = (int) ($result['risk_score'] ?? 0);
        $triggeredRules = $result['triggered_rules'] ?? [];
        $reasonSummary = $result['reason_summary'] ?? null;

        /**
         * R4) Unfamiliar device -> STEP_UP
         * Applies only when we actually know the user, have a device_id,
         * and MFA has NOT been verified yet.
         */
        $mfaVerified = (bool) ($data['mfa_verified'] ?? false);
        if (!$mfaVerified && !empty($userId) && !empty($deviceId)) {
            $known = UserDevice::query()
                ->where('user_id', $userId)
                ->where('device_id', $deviceId)
                ->exists();

            if (!$known) {
                $already = false;
                foreach ($triggeredRules as $r) {
                    if (($r['code'] ?? null) === 'R4_NEW_DEVICE') { $already = true; break; }
                }
                if (!$already) {
                    $triggeredRules[] = [
                        'code' => 'R4_NEW_DEVICE',
                        'detail' => 'Unfamiliar device_id for user',
                    ];
                }

                // bump risk; keep BLOCK if already BLOCK
                $riskScore += 55;

                if ($decision !== 'BLOCK') {
                    $decision = 'STEP_UP';
                }

                if (!$reasonSummary) $reasonSummary = 'R4_NEW_DEVICE';
            }
        }

        // 3) persist FraudFlag for STEP_UP/BLOCK
        $flag = null;
        if ($decision !== 'ALLOW') {
            $flag = FraudFlag::create([
                'correlation_id' => $data['correlation_id'] ?? null,
                'user_id' => $userId,
                'identifier' => $identifier,
                'decision' => $decision,
                'risk_score' => $riskScore,
                'reason_summary' => $reasonSummary,
                'triggered_rules' => $triggeredRules,
                'expires_at' => $decision === 'BLOCK' ? now()->addMinutes(10) : null,
            ]);
        }

        // 4) Update device registry ONLY after MFA verified
        if ($mfaVerified === true && !empty($userId) && !empty($deviceId)) {
            UserDevice::updateOrCreate(
                ['user_id' => $userId, 'device_id' => $deviceId],
                [
                    'first_seen_at' => now(),
                    'last_seen_at' => now(),
                    'last_ip' => $data['ip'] ?? null,
                    'last_user_agent_hash' => !empty($data['user_agent'])
                        ? hash('sha256', (string) $data['user_agent'])
                        : null,
                ]
            );
        }

        // 4B) Clear recent GEO anomaly flags after MFA is verified.
        // Otherwise R3B_GEO_COOLDOWN will keep forcing STEP_UP for the whole cooldown window.
        if ($mfaVerified === true && !empty($userId)) {
            $cooldownMinutes = 10;

            FraudFlag::query()
                ->where('user_id', $userId)
                ->where('created_at', '>=', now()->subMinutes($cooldownMinutes))
                ->whereRaw("JSON_SEARCH(triggered_rules, 'one', 'R3_GEO_ANOMALY', NULL, '$[*].code') IS NOT NULL")
                ->delete();
        }


        return response()->json([
            'stored_event_id' => $event->id,
            'decision' => $decision,
            'risk_score' => $riskScore,
            'triggered_rules' => $triggeredRules,
            'flag_id' => $flag?->id,
            'expires_in' => ($flag && $flag->decision === 'BLOCK' && $flag->expires_at)
                ? now()->diffInSeconds($flag->expires_at)
                : null,
        ]);
    }
}
