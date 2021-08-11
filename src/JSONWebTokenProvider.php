<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

use Firebase\JWT\JWT;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;

use function array_filter;
use function array_merge;
use function assert;
use function strtotime;
use function time;

class JSONWebTokenProvider implements TokenProvider
{
    private const CACHE_PREFIX_KEY = 'jwtInvalidated:';

    private string $notBefore = 'now';

    private string $timeToLive = '+5 minutes';

    private int $availableKeys = -1;

    private ?string $issuer;

    /** @var string|string[]|null */
    private string|array|null $audience;

    private bool $addExpiresIn = false;

    private ?int $testTimestamp;

    private string $refreshTokenTimeToLive = '+2 weeks';

    /**
     * @param AsymetricCipher[] $ciphers
     */
    public function __construct(
        private array $ciphers,
        private OpaqueTokenFactory $opaqueTokenFactory,
        private OpaqueTokenRepository $opaqueTokensRepository,
        private SubjectRepository $subjectRepository,
        private ClaimsHandler $claimsHandler,
        private EventDispatcherInterface $dispatcher,
        private CacheInterface $invalidateCache
    ) {
    }

    public function create(Subject $subject): TokenSet
    {
        $set = $this->createNewTokenSetFromSubject($subject);
        $this->dispatcher->dispatch(new TokenCreated($set, $subject));

        return $set;
    }

    private function createNewTokenSetFromSubject(Subject $subject): TokenSet
    {
        $now    = $this->now();
        $key    = $subject->getKey();
        $cipher = $this->ciphers[0];
        assert($cipher instanceof AsymetricCipher);
        $notBefore = strtotime($this->notBefore, $now);
        $expiresAt = strtotime($this->timeToLive, $now);

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'iat' => $now,
            'sub' => $key,
            'exp' => $expiresAt,
            'nbf' => $notBefore,
        ];

        if ($this->addExpiresIn) {
            $payload['exi'] = $expiresAt - $now;
        }

        $payload = array_filter(
            array_merge($payload, $this->claimsHandler->pack($subject)),
            static fn ($v) => $v !== null,
        );

        $jwt = JWT::encode(
            $payload,
            $cipher->getPrivateKey(),
            alg: $cipher->getName(),
            keyId: $cipher->getID(),
        );

        $refreshToken = $this->opaqueTokenFactory->create([
            'subject' => $key,
            'expiresAt' => strtotime($this->refreshTokenTimeToLive, $now),
        ]);

        $this->opaqueTokensRepository->create($refreshToken);

        return new TokenSet(
            new JSONWebToken($jwt, $payload),
            $refreshToken,
        );
    }

    public function decode(string $token): JSONWebToken
    {
        $keysMap     = [];
        $allowedAlgs = [];

        foreach ($this->ciphers as $cipher) {
            $keysMap[$cipher->getID()] = $cipher->getPublicKey();
            $allowedAlgs[]             = $cipher->getName();
        }

        $content = JWT::decode($token, $keysMap, $allowedAlgs);

        $key         = self::CACHE_PREFIX_KEY . $content->sub;
        $invalidated = $this->invalidateCache->get($key);

        if (! empty($invalidated) && $content->exp <= $invalidated) {
            throw new ExpiredJSONWebToken('The token is no longer valid');
        }

        return new JSONWebToken($token, (array) $content);
    }

    public function refresh(string $refreshToken): TokenSet
    {
        [$subject, $oldRefreshToken] = $this->invalidateToken($refreshToken);
        $newTokenSet                 = $this->createNewTokenSetFromSubject($subject);
        $this->dispatcher->dispatch(
            new TokenRefreshed(
                $newTokenSet,
                $oldRefreshToken,
                $subject,
            ),
        );

        return $newTokenSet;
    }

    public function revoke(string $refreshToken): void
    {
        [$subject, $opaqueToken] = $this->invalidateToken($refreshToken);
        $key                     = self::CACHE_PREFIX_KEY . $subject->getKey();
        $ttl                     = strtotime($this->timeToLive, $this->now());
        $this->invalidateCache->set($key, $ttl, $ttl);
        $this->dispatcher->dispatch(
            new TokenRevoked(
                $opaqueToken,
                $subject,
            ),
        );
    }

    /**
     * @return array{0: Subject, 1: OpaqueToken}
     */
    private function invalidateToken(string $refreshToken): array
    {
        $token   = $this->getRefreshToken($refreshToken);
        $subject = $this->subjectRepository->find($token->subject);
        $this->opaqueTokensRepository->delete($token);

        return [$subject, $token];
    }

    private function getRefreshToken(string $refreshToken): OpaqueToken
    {
        $token = $this->opaqueTokensRepository->find($refreshToken);

        if (empty($token)) {
            throw new InvalidRefreshToken('The given refresh token is no longer valid');
        }

        if ($token->expiresAt + JWT::$leeway <= $this->now()) {
            $this->opaqueTokensRepository->delete($token);

            throw new ExpiredRefreshToken('The given refresh token has expired');
        }

        return $token;
    }

    public function notBefore(string $notBefore): self
    {
        $this->notBefore = $notBefore;

        return $this;
    }

    public function timeToLive(string $timeToLive): self
    {
        $this->timeToLive = $timeToLive;

        return $this;
    }

    public function issuer(string $issuer): self
    {
        $this->issuer = $issuer;

        return $this;
    }

    /**
     * @param string|string[]|null $audience
     */
    public function audience(string|array|null $audience): self
    {
        $this->audience = $audience;

        return $this;
    }

    public function addExpiresInClaim(bool $value): self
    {
        $this->addExpiresIn = $value;

        return $this;
    }

    public function availableKeys(int $keys): self
    {
        $this->availableKeys = $keys;

        return $this;
    }

    private function now(): int
    {
        if (empty($this->testTimestamp)) {
            return time();
        }

        return $this->testTimestamp;
    }

    public function setTestTimestamp(?int $value): self
    {
        $this->testTimestamp = $value;
        JWT::$timestamp      = $value;

        return $this;
    }

    public function leeway(int $value): self
    {
        JWT::$leeway = $value;

        return $this;
    }

    public function refreshTokenTimeToLive(string $value): self
    {
        $this->refreshTokenTimeToLive = $value;

        return $this;
    }
}
