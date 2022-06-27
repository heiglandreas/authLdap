<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Wrapper;

class LdapFactory
{
	public function createFromLdapUri(string $ldapUri): LdapInterface
	{
		return new Ldap($ldapUri);
	}

	public function escape($value, $ignore = '', $flags = 0): string
	{
		return Ldap::escape($value, $ignore, $flags);
	}
}
