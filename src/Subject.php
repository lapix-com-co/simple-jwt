<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface Subject
{
    public function getKey(): string;
}
