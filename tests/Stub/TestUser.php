<?php

declare(strict_types=1);

namespace Tests\Stub;

use Lapix\SimpleJwt\Subject;

class TestUser implements Subject
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private string $key,
        private ?array $claims = [],
    ) {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    /** @return array<string, mixed> */
    public function getClaims(): ?array
    {
        return $this->claims;
    }
}
