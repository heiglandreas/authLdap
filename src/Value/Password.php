<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use InvalidArgumentException;

final class Password
{
	private string $password;
	private function __construct(string $password)
	{
		$this->password = $password;
	}

	/**
	 * @param mixed $password
	 */
	public static function fromMixed($password): self
	{
		global $error;
		if (! is_string($password)) {
			throw new InvalidArgumentException('provided password is not a string');
		}
		if ($password === '') {
			$error =  __('<strong>Error</strong>: The password field is empty.');
			throw new InvalidArgumentException('No password provided');
		}

		// Remove slashes as noted on https://github.com/heiglandreas/authLdap/issues/108
		return new self(stripslashes_deep($password));
	}

	public function __toString(): string
	{
		return $this->password;
	}
}
