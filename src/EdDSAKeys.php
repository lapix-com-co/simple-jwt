<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

class EdDSAKeys implements AsymetricCipher, EllipticCurveAware
{
    public function __construct(
        private string $publicKey,
        private string $privateKey,
        private ?string $id
    ) {
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getID(): ?string
    {
        return $this->id;
    }

    public function getName(): string
    {
        return 'EdDSA';
    }

    public function getType(): string
    {
        return 'OKP';
    }

    public function getEllipticCurveName(): string
    {
        return 'Ed25519';
    }
}
