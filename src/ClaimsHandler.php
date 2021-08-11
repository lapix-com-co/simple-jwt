<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface ClaimsHandler
{
    /**
     * @return array<string, mixed>
     */
    public function pack(Subject $subject): array;

    public function unpack(JSONWebToken $jwt): Subject;
}
