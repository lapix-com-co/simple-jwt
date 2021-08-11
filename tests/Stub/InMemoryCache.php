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
    public function get($key, $default = null)
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
    public function set($key, $value, $ttl = null)
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
    public function delete($key)
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
    public function clear()
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
    public function getMultiple($keys, $default = null)
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
    public function setMultiple($values, $ttl = null)
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
    public function deleteMultiple($keys)
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function has($key)
    {
        return ! isset($this->items[$key]);
    }
}
