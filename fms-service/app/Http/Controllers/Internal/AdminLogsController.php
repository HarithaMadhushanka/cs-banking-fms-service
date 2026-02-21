<?php

namespace App\Http\Controllers\Internal;

use App\Http\Controllers\Controller;
use App\Models\FraudFlag;
use Illuminate\Http\Request;

class AdminLogsController extends Controller
{
    public function index(Request $request)
    {
        $perPage = min(100, max(10, (int) $request->input('per_page', 25)));

        return response()->json(
            FraudFlag::query()->orderByDesc('id')->paginate($perPage)
        );
    }
}