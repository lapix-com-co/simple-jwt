<?php

declare(strict_types=1);

namespace Tests;

use Lapix\SimpleJwt\EdDSAKeys;
use Lapix\SimpleJwt\ExpiredJSONWebToken;
use Lapix\SimpleJwt\ExpiredRefreshToken;
use Lapix\SimpleJwt\InvalidRefreshToken;
use Lapix\SimpleJwt\JSONWebTokenProvider;
use Lapix\SimpleJwt\StringGenerator;
use Lapix\SimpleJwt\TokenCreated;
use Lapix\SimpleJwt\TokenRefreshed;
use Lapix\SimpleJwt\TokenRevoked;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Tests\Stub\InMemoryCache;
use Tests\Stub\InMemorySubjectRepository;
use Tests\Stub\InMemoryTokenRepository;
use Tests\Stub\TestUser;
use Tests\Stub\TestUserClaimsHandler;

use function base64_encode;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;

/**
 * @uses \Lapix\SimpleJwt\EdDSAKeys
 * @uses \Lapix\SimpleJwt\Token
 * @uses \Lapix\SimpleJwt\TokenSet
 * @uses \Lapix\SimpleJwt\TokenCreated
 * @uses \Lapix\SimpleJwt\TokenRevoked
 * @uses \Lapix\SimpleJwt\TokenRefreshed
 *
 * @covers \Lapix\SimpleJwt\JWTTokenProvider
 */
class CreateTokenTest extends TestCase
{
    /** @var EventDispatcherInterface&MockObject */
    private $dispatcherMock;

    public function setup(): void
    {
        parent::setup();

        $this->dispatcherMock = $this->createMock(EventDispatcherInterface::class);
    }

    public function testCreateToken(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());

        $token = $provider->create($subject);

        $this->assertNotEmpty($token);
    }

    public function testDecodedKeyIsValid(): void
    {
        $subject  = new TestUser('qwerty', ['email' => 'john@google.com']);
        $provider = $this->configureProvider($this->newJWTTokenProvider());

        $token   = $provider->create($subject);
        $decoded = $provider->decode($token->getJWT()->getToken());

        $this->assertEquals($decoded->sub, 'qwerty');
        $this->assertEquals($decoded->email, 'john@google.com');
    }

    public function testDateValues(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider())
            ->setTestTimestamp(1000);

        $token   = $provider->create($subject);
        $decoded = $provider->decode($token->getJWT()->getToken());

        $this->assertEquals($decoded->iat, 1000);
        $this->assertEquals($decoded->nbf, 1000);
        $this->assertEquals($decoded->exi, 60 * 2);
        $this->assertEquals($decoded->exp, 1000 + (60 * 2));
    }

    public function testRefreshToken(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider())
            ->setTestTimestamp(1000);

        $tokens = $provider->create($subject);
        $provider->setTestTimestamp(2000);
        $refreshed = $provider->refresh($tokens->getRefreshToken()->getToken());

        $this->assertNotEquals(
            $tokens->getJWT()->getToken(),
            $refreshed->getJWT()->getToken(),
        );
        $this->assertNotEquals(
            $tokens->getRefreshToken()->getToken(),
            $refreshed->getRefreshToken()->getToken(),
        );
    }

    public function testUsedTokenIsInvalidated(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());
        $tokens   = $provider->create($subject);
        $provider->refresh($tokens->getRefreshToken()->getToken());

        $this->expectException(InvalidRefreshToken::class);

        $provider->refresh($tokens->getRefreshToken()->getToken());
    }

    public function testInvalidRefreshTokensAreRejected(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());

        $this->expectException(InvalidRefreshToken::class);

        $provider->refresh('qwerty');
    }

    public function testRevokeToken(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());
        $tokens   = $provider->create($subject);
        $provider->revoke($tokens->getRefreshToken()->getToken());

        $this->expectException(InvalidRefreshToken::class);

        $provider->refresh($tokens->getRefreshToken()->getToken());
    }

    public function testDispatchEventAfterCreating(): void
    {
        $this->dispatcherMock->expects($this->once())
            ->method('dispatch')
            ->with($this->isInstanceOf(TokenCreated::class));

        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());
        $provider->create($subject);
    }

    public function testDispatchEventAfterRefresing(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());
        $tokens   = $provider->create($subject);

        $this->dispatcherMock->expects($this->once())
            ->method('dispatch')
            ->with($this->isInstanceOf(TokenRefreshed::class));

        $provider->refresh($tokens->getRefreshToken()->getToken());
    }

    public function testDispatchEventAfterInvalidating(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider());
        $tokens   = $provider->create($subject);

        $this->dispatcherMock->expects($this->once())
            ->method('dispatch')
            ->with($this->isInstanceOf(TokenRevoked::class));

        $provider->revoke($tokens->getRefreshToken()->getToken());
    }

    public function testExpiredOpaqueTokens(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider())
            ->setTestTimestamp(1000);
        $tokens   = $provider->create($subject);
        // Add 3 week and 60 seconds of leeway to make the refresh token expires.
        $provider->setTestTimestamp(1000 + (60 * 60 * 24 * 7 * 3) + 60);

        $this->expectException(ExpiredRefreshToken::class);

        $provider->refresh($tokens->getRefreshToken()->getToken());
    }

    public function testJWTTokensAreNotLongerValidAfterRevoking(): void
    {
        $subject  = new TestUser('qwerty', []);
        $provider = $this->configureProvider($this->newJWTTokenProvider())
            ->setTestTimestamp(1000);
        $tokens   = $provider->create($subject);
        $provider->revoke($tokens->getRefreshToken()->getToken());

        $this->expectException(ExpiredJSONWebToken::class);

        $provider->decode($tokens->getJWT()->getToken());
    }

    private function newEdDSAKey(?string $key = null): EdDSAKeys
    {
        $keyPair    = sodium_crypto_sign_keypair();
        $privateKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));
        $publicKey  = base64_encode(sodium_crypto_sign_publickey($keyPair));

        return new EdDSAKeys($publicKey, $privateKey, $key);
    }

    private function configureProvider(JSONWebTokenProvider $provider): JSONWebTokenProvider
    {
        return $provider->notBefore('now')
            ->timeToLive('+2 minutes')
            ->availableKeys(2)
            ->issuer('http://macondo.com')
            ->audience(['value1', 'value2'])
            ->leeway(60)
            // Remove the fixed time stamp.
            ->setTestTimestamp(null)
            ->refreshTokenTimeToLive('+3 weeks')
            ->addExpiresInClaim(true);
    }

    private function newJWTTokenProvider(): JSONWebTokenProvider
    {
        return new JSONWebTokenProvider(
            [$this->newEdDSAKey('1')],
            new StringGenerator(),
            new InMemoryTokenRepository(),
            new InMemorySubjectRepository([new TestUser('qwerty')]),
            new TestUserClaimsHandler(),
            $this->dispatcherMock,
            new InMemoryCache(),
        );
    }
}
