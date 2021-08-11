<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface ClaimsHandler
{
    /**
     * @return array<string, mixed>
     */
    public function pack(object $subject): array;

    public function unpack(JSONWebToken $jwt): object;

    public function getSubject(object $user): string;
}
