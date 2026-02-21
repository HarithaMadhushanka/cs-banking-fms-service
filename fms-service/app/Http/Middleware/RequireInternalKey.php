<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RequireInternalKey
{
    public function handle(Request $request, Closure $next)
    {
        $key = $request->header('X-Internal-Key');
        if (!$key || $key !== env('INTERNAL_SERVICE_KEY')) {
            return response()->json(['message' => 'forbidden'], 403);
        }
        return $next($request);
    }
}