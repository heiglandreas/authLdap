<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class NameAttribute
{
	private string $nameAttribute;
	private function __construct(string $nameAttribute)
	{
		$this->nameAttribute = $nameAttribute;
	}

	public static function fromString(string $nameAttribute = ''): self
	{
		return new self($nameAttribute);
	}

	public function __toString(): string
	{
		if ($this->nameAttribute === '') {
			return 'name';
		}

		return $this->nameAttribute;
	}
}
