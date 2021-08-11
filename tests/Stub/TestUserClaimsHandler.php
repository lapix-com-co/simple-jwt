<?php

declare(strict_types=1);

namespace Tests\Stub;

use Exception;
use Lapix\SimpleJwt\ClaimsHandler;
use Lapix\SimpleJwt\JSONWebToken;
use Lapix\SimpleJwt\Subject;

class TestUserClaimsHandler implements ClaimsHandler
{
    /**
     * {@inheritDoc}
     */
    public function pack(Subject $subject): array
    {
        if (! ($subject instanceof TestUser)) {
            throw new Exception('The given user is not a TestUser');
        }

        return $subject->getClaims();
    }

    public function unpack(JSONWebToken $jwt): Subject
    {
        return new TestUser($jwt->sub, $jwt->getProperties());
    }
}
