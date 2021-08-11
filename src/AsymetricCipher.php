<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface AsymetricCipher
{
    public function getName(): string;

    public function getPrivateKey(): string;

    public function getPublicKey(): string;

    public function getID(): ?string;
}
