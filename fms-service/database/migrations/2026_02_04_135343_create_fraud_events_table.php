<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fraud_events', function (Blueprint $table) {
            $table->id();
            $table->string('correlation_id', 64)->nullable()->index();

            $table->string('event_type', 64); // e.g. login_attempt

            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('identifier', 191)->nullable()->index(); // email/username

            $table->string('ip', 64)->nullable()->index();
            $table->text('user_agent')->nullable();

            $table->boolean('success')->default(false);

            $table->string('country', 2)->nullable();
            $table->string('city', 128)->nullable();
            $table->decimal('lat', 10, 7)->nullable();
            $table->decimal('lon', 10, 7)->nullable();

            $table->timestamp('occurred_at')->index();
            $table->timestamps();
        });
    }


    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('fraud_events');
    }
};
