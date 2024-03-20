<?php

declare(strict_types=1);

namespace Tests\Stub;

use Psr\SimpleCache\CacheInterface;

use function time;

class InMemoryCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $items = [];

    /**
     * {@inheritDoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if (! isset($this->items[$key])) {
            return $default;
        }

        $item = $this->items[$key];

        if ($item['ttl'] > time()) {
            return $default;
        }

        return $item['value'];
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->items[$key] = [
            'value' => $value,
            'ttl' => $ttl,
        ];

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function delete(string $key): bool
    {
        if (! isset($this->items[$key])) {
            return true;
        }

        unset($this->items[$key]);

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    /**
     * @param string[] $keys
     *
     * @return mixed[]
     *
     * {@inheritDoc}
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];

        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $values
     *
     * {@inheritDoc}
     */
    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    /**
     * @param string[] $keys
     *
     * {@inheritDoc}
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function has(string $key): bool
    {
        return ! isset($this->items[$key]);
    }
}
