<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\V1\LoginAttemptController;
use App\Http\Controllers\Internal\AdminLogsController as InternalAdminLogsController;
use App\Http\Controllers\Internal\AdminDeviceController;



Route::get('/health', function () {
    return response()->json([
        'service' => 'fms-service',
        'status' => 'ok',
        'time' => now()->toIso8601String(),
    ]);
});
Route::post('/v1/events/login-attempt', [LoginAttemptController::class, 'store']);
Route::middleware(['internal.key'])->group(function () {
    Route::get('/internal/admin/logs', [InternalAdminLogsController::class, 'index']);
    Route::get('/internal/admin/devices', [AdminDeviceController::class, 'index']);
});