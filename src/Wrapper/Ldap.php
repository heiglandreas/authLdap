<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Wrapper;

use function ldap_bind;
use function ldap_connect;
use function ldap_error;
use function ldap_escape;
use function ldap_get_entries;
use function ldap_set_option;
use function ldap_start_tls;
use function ldap_unbind;
use function var_dump;

final class Ldap implements LdapInterface
{
	private $connection;

	public function __construct(string $ldapUri)
	{
		$this->connection = ldap_connect($ldapUri);
	}

	public function bind($dn = null, $password = null)
	{
		if (null === $dn && null === $password) {
			return ldap_bind($this->connection);
		}
		return ldap_bind($this->connection, $dn, $password);
	}

	public function unbind()
	{
		return ldap_unbind($this->connection);
	}

	public function setOption($option, $value)
	{
		return ldap_set_option($this->connection, $option, $value);
	}

	public function startTls()
	{
		return ldap_start_tls($this->connection);
	}

	public function error()
	{
		return ldap_error($this->connection);
	}

	public function errno()
	{
		return ldap_errno($this->connection);
	}

	public function search(
		$base,
		$filter,
		array $attributes = [],
		$attributes_only = 0,
		$sizelimit = -1,
		$timelimit = -1
	) {
		return ldap_search(
			$this->connection,
			$base,
			$filter,
			$attributes,
			$attributes_only,
			$sizelimit,
			$timelimit
		);
	}

	public function getEntries($search_result)
	{
		return ldap_get_entries($this->connection, $search_result);
	}

	public static function escape(string $value, string $ignore = '', int $flags = 0): string
	{
		return ldap_escape($value, $ignore, $flags);
	}
}
