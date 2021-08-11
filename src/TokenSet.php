<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class TokenSet
{
    public function __construct(
        private JSONWebToken $jwt,
        private OpaqueToken $refreshToken
    ) {
    }

    public function getJWT(): JSONWebToken
    {
        return $this->jwt;
    }

    public function getRefreshToken(): OpaqueToken
    {
        return $this->refreshToken;
    }
}
