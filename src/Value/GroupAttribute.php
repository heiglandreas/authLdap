<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class GroupAttribute
{
	private string $groupAttribute;
	private function __construct(string $groupAttribute)
	{
		$this->groupAttribute = $groupAttribute;
	}

	public static function fromString(string $groupAttribute = ''): self
	{
		return new self($groupAttribute);
	}

	public function __toString(): string
	{
		if ($this->groupAttribute === '') {
			return 'gidnumber';
		}

		return strtolower($this->groupAttribute);
	}
}
