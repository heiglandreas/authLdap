<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Exception;

use RuntimeException;

class MissingValidLdapConnection extends Error
{
	public static function get(): self
	{
		return new self(sprintf(
			'No valid LDAP connection available'
		));
	}
}
