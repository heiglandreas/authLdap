<?php

declare(strict_types=1);

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licensed under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdap;

use Org_Heigl\AuthLdap\Exception\UnknownOption;
use function array_key_exists;

class Options
{
	public const ENABLED = 'Enabled';
	public const CACHE_PW = 'CachePW';
	public const URI = 'URI';
	public const URI_SEPARATOR = 'URISeparator';
	public const FILTER = 'Filter';
	public const NAME_ATTR = 'NameAttr';
	public const SEC_NAME = 'SecName';
	public const UID_ATTR = 'UidAttr';
	public const MAIL_ATTR = 'MailAttr';
	public const WEB_ATTR = 'WebAttr';
	public const GROUPS = 'Groups';
	public const DEBUG = 'Debug';
	public const GROUP_ATTR = 'GroupAttr';
	public const GROUP_FILTER = 'GroupFilter';
	public const DEFAULT_ROLE = 'DefaultRole';
	public const GROUP_ENABLE = 'GroupEnable';
	public const GROUP_OVER_USER = 'GroupOverUser';
	public const VERSION = 'Version';
	public const DO_NOT_OVERWRITE_NON_LDAP_USERS = 'DoNotOverwriteNonLdapUsers';

	private array $settings = [
			'Enabled' => false,
			'CachePW' => false,
			'URI' => '',
			'URISeparator' => ' ',
			'Filter' => '', // '(uid=%s)'
			'NameAttr' => '', // 'name'
			'SecName' => '',
			'UidAttr' => '', // 'uid'
			'MailAttr' => '', // 'mail'
			'WebAttr' => '',
			'Groups' => [],
			'Debug' => false,
			'GroupAttr' => '', // 'gidNumber'
			'GroupFilter' => '', // '(&(objectClass=posixGroup)(memberUid=%s))'
			'DefaultRole' => '',
			'GroupEnable' => true,
			'GroupOverUser' => true,
			'Version' => 1,
			'DoNotOverwriteNonLdapUsers' => false,
		];

	public function get(string $key)
	{
		if (! array_key_exists($key, $this->settings)) {
			throw UnknownOption::withKey($key);
		}

		return $this->settings[$key];
	}

	public function has(string $key): bool
	{
		return array_key_exists($key, $this->settings);
	}

	/**
	 * @param mixed $value
	 */
	public function set(string $key, $value): void
	{
		if (! array_key_exists($key, $this->settings)) {
			throw UnknownOption::withKey($key);
		}

		$this->settings[$key] = $value;
	}

	public function toArray(): array
	{
		return $this->settings;
	}
}
