<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class TokenCreated
{
    public function __construct(
        private TokenSet $token,
        private Subject $subject
    ) {
    }

    public function getToken(): TokenSet
    {
        return $this->token;
    }

    public function getSubject(): Subject
    {
        return $this->subject;
    }
}
