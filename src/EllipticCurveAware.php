<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface EllipticCurveAware
{
    public function getEllipticCurveName(): string;
}
