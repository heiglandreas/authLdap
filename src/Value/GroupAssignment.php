<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use InvalidArgumentException;

final class GroupAssignment
{
	private string $wordPressRole;

	private string $ldapGroups;

	private function __construct(string $wordPressRole, string $ldapGroups)
	{
		$this->wordPressRole = $wordPressRole;
		$this->ldapGroups = $ldapGroups;
	}

	/**
	 * @param mixed $username
	 */
	public static function fromKeyValue(string $key, string $value): self
	{
		return new self($key, trim($value));
	}

	public function getRole(): string
	{
		return $this->wordPressRole;
	}

	public function getGroups(): string
	{
		return $this->ldapGroups;
	}
}
