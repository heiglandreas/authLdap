<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class GroupSeparator
{
	private string $groupSeparator;
	private function __construct(string $groupSeparator) {
		$this->groupSeparator = $groupSeparator;
	}

	public static function fromString(string $groupSeparator = ''): self
	{
		return new self($groupSeparator);
	}

	public function __toString(): string
	{
		if ($this->groupSeparator === '') {
			return ',';
		}

		return $this->groupSeparator;
	}
}
