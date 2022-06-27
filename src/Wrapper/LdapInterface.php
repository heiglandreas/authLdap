<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Wrapper;

interface LdapInterface
{
	public function bind($dn = null, $password = null);

	public function unbind();

	public function setOption($option, $value);

	public function startTls();

	public function error();

	public function errno();

	public function search(
		$base,
		$filter,
		array $attributes = [],
		$attributes_only = 0,
		$sizelimit = -1,
		$timelimit = -1
	);

	public function getEntries($search_result);

	public static function escape(string $value, string $ignore = '', int $flags = 0): string;
}
