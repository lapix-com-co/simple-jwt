<?php

declare(strict_types=1);

namespace Lapix\SimpleJwt;

use DomainException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
use UnexpectedValueException;

use function array_filter;
use function array_merge;
use function assert;
use function count;
use function min;
use function rand;
use function strtotime;
use function time;

class JSONWebTokenProvider implements TokenProvider
{
    public static ?int $randomKey = null;

    private const CACHE_PREFIX_KEY = 'jwtInvalidated:';

    private string $notBefore = 'now';

    private string $timeToLive = '+5 minutes';

    private int $availableKeys = -1;

    private ?string $issuer = null;

    /** @var string|string[]|null */
    private string|array|null $audience = null;

    private bool $addExpiresIn = false;

    private ?int $testTimestamp = null;

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

    public function create(object $subject): TokenSet
    {
        $set = $this->createNewTokenSetFromSubject($subject);
        $this->dispatcher->dispatch(new TokenCreated($set, $subject));

        return $set;
    }

    public function createJWT(object $subject): JSONWebToken
    {
        return $this->createNewJWTTokenFromSubject($this->now(), $subject);
    }

    private function getCipher(): AsymetricCipher
    {
        if (empty($this->ciphers)) {
            throw new DomainException('ciphers list can\'t be empty');
        }

        if (count($this->ciphers) === 1) {
            return $this->ciphers[0];
        }

        $use = self::$randomKey ?? rand(0, count($this->ciphers));

        if ($this->availableKeys !== -1) {
            $use = min($use, $this->availableKeys);
        }

        return $this->ciphers[$use - 1];
    }

    private function createNewJWTTokenFromSubject(int $now, object $subject): JSONWebToken
    {
        $key    = $this->claimsHandler->getSubject($subject);
        $cipher = $this->getCipher();
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

        return new JSONWebToken($jwt, array_merge($payload, [
            'alg' => $cipher->getName(),
            'kid' => $cipher->getID(),
        ]));
    }

    private function createNewOpaqueTokenFromSubject(int $now, object $subject): OpaqueToken
    {
        $key = $this->claimsHandler->getSubject($subject);

        $refreshToken = $this->opaqueTokenFactory->create([
            'subject' => $key,
            'expiresAt' => strtotime($this->refreshTokenTimeToLive, $now),
        ]);

        $this->opaqueTokensRepository->create($refreshToken);

        return $refreshToken;
    }

    private function createNewTokenSetFromSubject(object $subject): TokenSet
    {
        $now = $this->now();

        return new TokenSet(
            $this->createNewJWTTokenFromSubject($now, $subject),
            $this->createNewOpaqueTokenFromSubject($now, $subject),
        );
    }

    public function decode(string $token): JSONWebToken
    {
        $content     = null;
        $keysMap     = [];
        $allowedAlgs = [];

        foreach ($this->ciphers as $cipher) {
            $keysMap[$cipher->getID()] = $cipher->getPublicKey();
            $allowedAlgs[]             = $cipher->getName();
        }

        try {
            $content = JWT::decode($token, $keysMap, $allowedAlgs);
        } catch (ExpiredException $e) {
            throw new ExpiredJSONWebToken('The token is no longer valid');
        } catch (UnexpectedValueException $e) {
            throw new InvalidJSONWebToken($e->getMessage());
        } catch (DomainException $e) {
            throw new InvalidJSONWebToken($e->getMessage());
        }

        $key         = self::CACHE_PREFIX_KEY . $content->sub;
        $invalidated = $this->invalidateCache->get($key);

        if (! empty($invalidated) && $content->exp <= $invalidated) {
            throw new ExpiredJSONWebToken('The token is no longer valid');
        }

        return new JSONWebToken($token, (array) $content);
    }

    public function refresh(string $refreshToken): TokenSet
    {
        [$subject, $oldRefreshToken] = $this->invalidateToken($refreshToken, 'refresh');
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
        [$subject, $opaqueToken] = $this->invalidateToken($refreshToken, 'revoke');
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
     * @return array{0: object, 1: OpaqueToken}
     */
    private function invalidateToken(string $refreshToken, string $action): array
    {
        $token   = $this->getRefreshToken($refreshToken);
        $subject = $this->subjectRepository->find($token->subject);

        $this->dispatcher->dispatch(
            new InvalidatingToken($token, $subject, $action),
        );

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
        $this->availableKeys = min($keys, count($this->ciphers));

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
