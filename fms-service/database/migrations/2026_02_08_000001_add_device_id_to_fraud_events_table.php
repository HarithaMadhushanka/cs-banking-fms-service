<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('fraud_events', function (Blueprint $table) {
            $table->string('device_id', 128)->nullable()->after('identifier')->index();
        });
    }

    public function down(): void
    {
        Schema::table('fraud_events', function (Blueprint $table) {
            $table->dropColumn('device_id');
        });
    }
};
