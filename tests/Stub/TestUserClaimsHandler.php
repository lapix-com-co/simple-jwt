<?php

declare(strict_types=1);

namespace Tests\Stub;

use Exception;
use Lapix\SimpleJwt\ClaimsHandler;
use Lapix\SimpleJwt\JSONWebToken;

class TestUserClaimsHandler implements ClaimsHandler
{
    /**
     * {@inheritDoc}
     */
    public function pack(object $subject): array
    {
        if (! ($subject instanceof TestUser)) {
            throw new Exception('The given user is not a TestUser');
        }

        return $subject->getClaims();
    }

    public function unpack(JSONWebToken $jwt): object
    {
        return new TestUser($jwt->sub, $jwt->getProperties());
    }

    public function getSubject(object $user): string
    {
        if (! ($user instanceof TestUser)) {
            throw new Exception('The given user is not a TestUser');
        }

        return $user->getKey();
    }
}
