<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface OpaqueTokenFactory
{
    /**
     * @param array<string, mixed> $options Additional value that will be related to the opaque token.
     */
    public function create(array $options): OpaqueToken;
}
