<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class FraudEvent extends Model
{
    protected $fillable = [
        'correlation_id',
        'event_type',
        'user_id',
        'identifier',
        'device_id',
        'ip',
        'user_agent',
        'success',
        'country',
        'city',
        'lat',
        'lon',
        'occurred_at',
    ];

    protected $casts = [
        'success' => 'boolean',
        'occurred_at' => 'datetime',
        'lat' => 'decimal:7',
        'lon' => 'decimal:7',
    ];
}
