<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class WebAttribute
{
	private string $webAttribute;
	private function __construct(string $webAttribute) {
		$this->webAttribute = $webAttribute;
	}

	public static function fromString(string $webAttribute = ''): self
	{
		return new self($webAttribute);
	}

	public function __toString(): string
	{
		if ($this->webAttribute === '') {
			return '';
		}

		return $this->webAttribute;
	}
}
