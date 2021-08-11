<?php

declare(strict_types=1);

namespace Tests\Stub;

use Lapix\SimpleJwt\SubjectRepository;

class InMemorySubjectRepository implements SubjectRepository
{
    /** @var array<string, object> */
    private array $items = [];

    /** @param array<object> $items */
    public function __construct(array $items)
    {
        foreach ($items as $item) {
            $this->items[$item->getKey()] = $item;
        }
    }

    public function find(string $id): ?object
    {
        if (empty($this->items[$id])) {
            return null;
        }

        return $this->items[$id];
    }
}
