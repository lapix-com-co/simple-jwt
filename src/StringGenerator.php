<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

use function base64_encode;
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
        $token = base64_encode($options['subject']) . '.' . base64_encode(random_bytes($this->tokenLength));

        return new OpaqueToken($token, $options);
    }
}
