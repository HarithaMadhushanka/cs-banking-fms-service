<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fraud_flags', function (Blueprint $table) {
            $table->id();
            $table->string('correlation_id', 64)->nullable()->index();

            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('identifier', 191)->nullable()->index();

            $table->string('decision', 16); // ALLOW | STEP_UP | BLOCK
            $table->unsignedInteger('risk_score')->default(0);

            $table->string('reason_summary', 255)->nullable();
            $table->json('triggered_rules')->nullable();

            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamps();
        });
    }


    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('fraud_flags');
    }
};
