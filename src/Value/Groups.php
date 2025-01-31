<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use Iterator;

final class Groups
{
	private array $groups;
	private function __construct(GroupAssignment ...$groups)
	{
		foreach ($groups as $group) {
			$this->groups[$group->getRole()] = $group->getGroups();
		}
	}

	public static function fromArray(array $groups): self
	{
		$assignements = [];
		foreach ($groups as $key => $group) {
			$assignements[] = GroupAssignment::fromKeyValue($key, $group);
		}
		return new self(...$assignements);
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
