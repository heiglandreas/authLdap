<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Exception;

use RuntimeException;

use function sprintf;

class InvalidLdapUri extends RuntimeException
{
	public static function cannotparse(string $ldapUri): self
	{
		return new self(sprintf(
			'%1$s seems not to be a valid URI',
			$ldapUri
		));
	}

	public static function wrongSchema(string $uri): self
	{
		return new self(sprintf(
			'%1$s does not start with a valid schema',
			$uri
		));
	}

	public static function noSchema(string $uri): self
	{
		return new self(sprintf(
			'%1$s does not provide a schema',
			$uri
		));
	}

	public static function noEnvironmentVariableSet(string $uri): self
	{
		return new self(sprintf(
			'The environment variable %1$s does not provide a URI',
			$uri
		));
	}

	public static function noServerProvided(string $uri): self
	{
		return new self(sprintf(
			'The LDAP-URI %1$s does not provide a server',
			$uri
		));
	}

	public static function noSearchBaseProvided(string $uri): self
	{
		return new self(sprintf(
			'The LDAP-URI %1$s does not provide a search-base',
			$uri
		));
	}

	public static function invalidSearchBaseProvided(string $uri): self
	{
		return new self(sprintf(
			'The LDAP-URI %1$s does not provide a valid search-base',
			$uri
		));
	}
}
