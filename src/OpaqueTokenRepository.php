<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface OpaqueTokenRepository
{
    public function find(string $token): ?OpaqueToken;

    public function create(OpaqueToken $token): void;

    public function delete(OpaqueToken $token): void;
}
