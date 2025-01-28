<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class UidAttribute
{
	private string $uidAttribute;
	private function __construct(string $uidAttribute) {
		$this->uidAttribute = $uidAttribute;
	}

	public static function fromString(string $uidAttribute = ''): self
	{
		return new self($uidAttribute);
	}

	public function __toString(): string
	{
		if ($this->uidAttribute === '') {
			return 'uid';
		}

		return strtolower($this->uidAttribute);
	}
}
