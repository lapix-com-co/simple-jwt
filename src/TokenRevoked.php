<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class TokenRevoked
{
    public function __construct(
        private OpaqueToken $oldRefreshToken,
        private object $subject
    ) {
    }

    public function getOldRefreshToken(): OpaqueToken
    {
        return $this->oldRefreshToken;
    }

    public function getSubject(): object
    {
        return $this->subject;
    }
}
