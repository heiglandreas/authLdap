<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use InvalidArgumentException;

final class Username
{
	private string $username;
	private function __construct(string $username) {
		$this->username = $username;
	}

	/**
	 * @param mixed $username
	 */
	public static function fromMixed($username): self
	{
		if (! is_string($username)) {
			throw new InvalidArgumentException('No valid username provided');
		}
		if ($username === '') {
			throw new InvalidArgumentException('No username provided');
		}

		return new self($username);
	}

	public function __toString(): string
	{
		return $this->username;
	}
}
