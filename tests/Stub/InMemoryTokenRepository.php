<?php

declare(strict_types=1);

namespace Tests\Stub;

use Lapix\SimpleJwt\OpaqueToken;
use Lapix\SimpleJwt\OpaqueTokenRepository;

class InMemoryTokenRepository implements OpaqueTokenRepository
{
    /** @var array<string, mixed> */
    private array $tokens = [];

    public function find(string $token): ?OpaqueToken
    {
        if (empty($this->tokens[$token])) {
            return null;
        }

        return $this->tokens[$token];
    }

    public function create(OpaqueToken $token): void
    {
        $this->tokens[$token->getToken()] = $token;
    }

    public function delete(OpaqueToken $token): void
    {
        if (empty($this->tokens[$token->getToken()])) {
            return;
        }

        unset($this->tokens[$token->getToken()]);
    }
}
