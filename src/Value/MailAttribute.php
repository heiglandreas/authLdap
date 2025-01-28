<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class MailAttribute
{
	private string $mailAttribute;
	private function __construct(string $mailAttribute) {
		$this->mailAttribute = $mailAttribute;
	}

	public static function fromString(string $mailAttribute = ''): self
	{
		return new self($mailAttribute);
	}

	public function __toString(): string
	{
		if ($this->mailAttribute === '') {
			return 'mail';
		}

		return $this->mailAttribute;
	}
}
