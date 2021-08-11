<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

use function random_bytes;

class StringGenerator implements OpaqueTokenFactory
{
    public function __construct(private int $tokenLength = 30)
    {
    }

    /**
     * @param array<string, mixed> $options
     */
    public function create(array $options): OpaqueToken
    {
        $token = $options['subject'] . ':' . random_bytes($this->tokenLength);

        return new OpaqueToken($token, $options);
    }
}
