<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class TokenRevoked
{
    public function __construct(
        private OpaqueToken $oldRefreshToken,
        private Subject $subject
    ) {
    }

    public function getOldRefreshToken(): OpaqueToken
    {
        return $this->oldRefreshToken;
    }

    public function getSubject(): Subject
    {
        return $this->subject;
    }
}
