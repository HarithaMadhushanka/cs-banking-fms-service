<?php

namespace App\Http\Controllers\Internal;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class AdminDeviceController extends Controller
{
    public function index(Request $request)
    {
        $perPage = max(1, min((int) $request->query('per_page', 10), 50));

        $q = DB::table('user_devices')
            ->select([
                'id',
                'user_id',
                'device_id',
                'first_seen_at',
                'last_seen_at',
                'last_ip',
                'last_user_agent_hash',
                'created_at',
                'updated_at',
            ])
            ->orderByDesc('last_seen_at')
            ->orderByDesc('id');

        // Optional filter: ?user_id=1
        if ($request->filled('user_id')) {
            $q->where('user_id', (int) $request->query('user_id'));
        }

        // Optional filter: ?device_id=demo-device-1
        if ($request->filled('device_id')) {
            $q->where('device_id', $request->query('device_id'));
        }

        return response()->json($q->paginate($perPage));
    }
}