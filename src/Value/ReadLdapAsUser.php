<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class ReadLdapAsUser
{
	private bool $enabled;
	private function __construct(bool $enabled)
	{
		$this->enabled = $enabled;
	}

	public static function fromString(string $enabled = ''): self
	{
		return new self(filter_var($enabled, FILTER_VALIDATE_BOOLEAN));
	}

	public function isEnabled(): bool
	{
		return $this->enabled;
	}
	public function __toString(): string
	{
		return $this->enabled ? 'true' : 'false';
	}
}
