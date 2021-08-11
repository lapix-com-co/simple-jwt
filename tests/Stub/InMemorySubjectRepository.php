<?php

declare(strict_types=1);

namespace Tests\Stub;

use Lapix\SimpleJwt\Subject;
use Lapix\SimpleJwt\SubjectRepository;

class InMemorySubjectRepository implements SubjectRepository
{
    /** @var array<string, Subject> */
    private array $items = [];

    /** @param array<Subject> $items */
    public function __construct(array $items)
    {
        foreach ($items as $item) {
            $this->items[$item->getKey()] = $item;
        }
    }

    public function find(string $id): ?Subject
    {
        if (empty($this->items[$id])) {
            return null;
        }

        return $this->items[$id];
    }
}
