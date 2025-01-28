<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class DefaultRole
{
	private string $defaultRole;
	private function __construct(string $defaultRole) {
		$this->defaultRole = $defaultRole;
	}

	public static function fromString(string $defaultRole = ''): self
	{
		return new self($defaultRole);
	}

	public function __toString(): string
	{
		return $this->defaultRole;
	}
}
