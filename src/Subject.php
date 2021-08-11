<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface Subject
{
    public function getKey(): string;

    /**
     * @return array<string, mixed>
     */
    public function getClaims(): ?array;
}
