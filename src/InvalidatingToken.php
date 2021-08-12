<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class InvalidatingToken
{
    public function __construct(
        private OpaqueToken $refreshToken,
        private object $subject
    ) {
    }

    public function getRefreshToken(): OpaqueToken
    {
        return $this->refreshToken;
    }

    public function getSubject(): object
    {
        return $this->subject;
    }
}
