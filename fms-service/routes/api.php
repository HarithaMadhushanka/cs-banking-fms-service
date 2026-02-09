<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\V1\LoginAttemptController;


Route::get('/health', function () {
    return response()->json([
        'service' => 'fms-service',
        'status' => 'ok',
        'time' => now()->toIso8601String(),
    ]);
});
Route::post('/v1/events/login-attempt', [LoginAttemptController::class, 'store']);