<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface SubjectRepository
{
    public function find(string $id): ?Subject;
}
