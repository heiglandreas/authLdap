<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class GroupBase
{
	private string $groupBase;
	private function __construct(string $groupBase)
	{
		$this->groupBase = $groupBase;
	}

	public static function fromString(string $groupBase = ''): self
	{
		return new self($groupBase);
	}

	public function __toString(): string
	{
		return $this->groupBase;
	}
}
