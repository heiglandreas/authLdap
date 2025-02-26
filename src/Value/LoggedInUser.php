<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

use InvalidArgumentException;

final class LoggedInUser
{
	private string $username;

	private string $password;

	private function __construct(
		string $username,
		#[\SensitiveParameter]
		string $password
	) {
		$this->username = $username;
		$this->password = $password;
	}

	/**
	 * @param mixed $username
	 */
	public static function fromUsernameAndPassword(Username $username, Password $password): self
	{
		return new self((string) $username, (string) $password);
	}

	public function getUsername(): string
	{
		return $this->username;
	}

	public function getPassword(): string
	{
		return $this->password;
	}
}
