<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

/**
 * TokenProvider implementer should generate a JTW token and a opaque token used to
 * generate a new JWT token.
 */
interface TokenProvider
{
    /**
     * Creates a new JWT token with the given subject.
     */
    public function create(Subject $subject): TokenSet;

    /**
     * Get the JWT with the given properties from a string value.
     */
    public function decode(string $token): JSONWebToken;

    /**
     * Creates a JWT Token and a refresh token, with a longer expiration time.
     * Should revoke the given refresh token.
     */
    public function refresh(string $refreshToken): TokenSet;

    /**
     * Should invalidate the refresh token. The JWT token should be provided for
     * security checks.
     */
    public function revoke(string $refreshToken): void;
}
