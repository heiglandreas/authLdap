<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Value;

final class GroupFilter
{
	private string $groupFilter;

	private string $dn;
	private function __construct(string $groupFilter, string $dn = '') {
		$this->groupFilter = $groupFilter;
		$this->dn = ldap_escape($dn, '', LDAP_ESCAPE_FILTER);
	}

	public function withDn(string $dn): self
	{
		return new self($this->groupFilter, $dn);
	}

	public static function fromString(string $groupFilter = ''): self
	{
		return new self($groupFilter);
	}

	public function __toString(): string
	{
		if ($this->groupFilter === '') {
			return '(&(objectClass=posixGroup)(memberUid=%s))';
		}

		return str_replace('%dn%', $this->dn, $this->groupFilter);
	}
}
