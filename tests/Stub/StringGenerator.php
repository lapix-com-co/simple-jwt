<?php

declare(strict_types=1);

namespace Tests\Stub;

use Lapix\SimpleJwt\OpaqueToken;
use Lapix\SimpleJwt\OpaqueTokenFactory;

use function array_merge;
use function count;
use function mt_rand;
use function range;

class StringGenerator implements OpaqueTokenFactory
{
    /**
     * @param array<string, mixed> $options
     */
    public function create(array $options): OpaqueToken
    {
        return new OpaqueToken($this->randomString(30), $options);
    }

    private function randomString(int $length): string
    {
        $keys = array_merge(range(0, 9), range('a', 'z'));
        $key  = '';

        for ($i = 0; $i < $length; $i++) {
            $key .= $keys[mt_rand(0, count($keys) - 1)];
        }

        return $key;
    }
}
