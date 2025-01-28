<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class UserFilter
{
	private string $userFilter;
	private function __construct(string $userFilter)
	{
		$this->userFilter = $userFilter;
	}

	public static function fromString(string $userFilter = ''): self
	{
		return new self($userFilter);
	}

	public function __toString(): string
	{
		if ($this->userFilter === '') {
			return '(uid=%s)';
		}

		return $this->userFilter;
	}
}
