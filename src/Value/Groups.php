<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use Iterator;

final class Groups
{
	private array $groups;
	private function __construct(string...$groups) {
		$this->groups = $groups;
	}

	public static function fromArray(array $groups): self
	{
		return new self(...$groups);
	}

	public function has(string $key): bool
	{
		return isset($this->groups[$key]);
	}

	public function get(string $key): string
	{
		if (!$this->has($key)) {
			return '';
		}
		return $this->groups[$key];
	}
}
