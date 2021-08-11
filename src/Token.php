<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class Token
{
    /**
     * @param array<string, mixed> $properties
     */
    public function __construct(
        private string $token,
        protected array $properties
    ) {
    }

    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return array<string, mixed>
     */
    public function getProperties(): array
    {
        return $this->properties;
    }

    public function __get(string $name): mixed
    {
        if (! isset($this->properties[$name])) {
            return null;
        }

        return $this->properties[$name];
    }
}
