<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class SecondNameAttribute
{
	private string $secondNameAttribute;
	private function __construct(string $secondNameAttribute) {
		$this->secondNameAttribute = $secondNameAttribute;
	}

	public static function fromString(string $secondNameAttribute = ''): self
	{
		return new self($secondNameAttribute);
	}

	public function __toString(): string
	{
		if ($this->secondNameAttribute === '') {
			return '';
		}

		return $this->secondNameAttribute;
	}
}
