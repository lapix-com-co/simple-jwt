<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

interface AsymetricCipher
{
    public function getName(): string;

    public function getPrivateKey(): string;

    public function getPublicKey(): string;

    /**
     * Returns the Key type also known as "kty".
     */
    public function getType(): string;

    public function getID(): ?string;
}
