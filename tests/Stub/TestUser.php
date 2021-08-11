<?php

declare(strict_types=1);

namespace Tests\Stub;

class TestUser
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
