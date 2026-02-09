<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class FraudFlag extends Model
{
    protected $fillable = [
        'correlation_id',
        'user_id',
        'identifier',
        'decision',
        'risk_score',
        'reason_summary',
        'triggered_rules',
        'expires_at',
    ];

    protected $casts = [
        'triggered_rules' => 'array',
        'expires_at' => 'datetime',
    ];
}
