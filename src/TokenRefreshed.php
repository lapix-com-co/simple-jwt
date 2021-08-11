<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class TokenRefreshed
{
    public function __construct(
        private TokenSet $newTokenSet,
        private OpaqueToken $oldRefreshToken,
        private Subject $subject
    ) {
    }

    public function getNewTokenSet(): TokenSet
    {
        return $this->newTokenSet;
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
