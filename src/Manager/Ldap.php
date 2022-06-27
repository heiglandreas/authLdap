<?php

/**
 * $Id: ldap.php 381646 2011-05-06 09:37:31Z heiglandreas $
 *
 * authLdap - Authenticate Wordpress against an LDAP-Backend.
 * Copyright (c) 2008 Andreas Heigl<andreas@heigl.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * This file handles the basic LDAP-Tasks
 *
 * @author Andreas Heigl<andreas@heigl.org>
 * @package authLdap
 * @category authLdap
 * @since 2008
 */

namespace Org_Heigl\AuthLdap\Manager;

use Org_Heigl\AuthLdap\Exception\Error;
use Org_Heigl\AuthLdap\Exception\MissingValidLdapConnection;
use Org_Heigl\AuthLdap\LdapUri;
use Org_Heigl\AuthLdap\Wrapper\LdapFactory;
use Org_Heigl\AuthLdap\Wrapper\LdapInterface;

class Ldap
{
	/**
	 * This property contains the connection handle to the ldap-server
	 *
	 * @var LdapInterface|null
	 */
	private ?LdapInterface $connection;

	private LdapUri $uri;

	private LdapFactory $factory;

	private $starttls;

	public function __construct(LdapFactory $factory, LdapUri $uri, $starttls = false)
	{
		$this->starttls = $starttls;
		$this->uri = $uri;
		$this->factory = $factory;
		$this->connection = null;
	}

	/**
	 * Connect to the given LDAP-Server
	 */
	public function connect(): self
	{
		$this->disconnect();

		$this->connection = $this->factory->createFromLdapUri($this->uri->toString());
		$this->connection->setOption(LDAP_OPT_PROTOCOL_VERSION, 3);
		$this->connection->setOption(LDAP_OPT_REFERRALS, 0);
		//if configured try to upgrade encryption to tls for ldap connections
		if ($this->starttls) {
			$this->connection->startTls();
		}
		return $this;
	}

	/**
	 * Disconnect from a resource if one is available
	 */
	public function disconnect(): self
	{
		if (null !== $this->connection) {
			$this->connection->unbind();
		}
		$this->connection = null;
		return $this;
	}

	/**
	 * Bind to an LDAP-Server with the given credentials
	 *
	 * @throws Error
	 */
	public function bind(): self
	{
		if (!$this->connection) {
			$this->connect();
		}
		if (null === $this->connection) {
			throw MissingValidLdapConnection::get();
		}
		if ($this->uri->isAnonymous()) {
			$bind = $this->connection->bind();
		} else {
			$bind = $this->connection->bind($this->uri->getUsername(), $this->uri->getPassword());
		}
		if (!$bind) {
			throw new Error('bind was not successfull: ' . $this->connection->error());
		}
		return $this;
	}

	/**
	 * This method does the actual ldap-serch.
	 *
	 * This is using the filter <var>$filter</var> for retrieving the attributes
	 * <var>$attributes</var>
	 *
	 * @return array<string|int, mixed>
	 * @throws Error
	 */
	public function search(string $filter, array $attributes = ['uid'], ?string $base = ''): array
	{
		if (null === $this->connection) {
			throw new Error('No resource handle available');
		}
		if (!$base) {
			$base = $this->uri->getBaseDn();
		}
		$result = $this->connection->search($base, $filter, $attributes);
		if ($result === false) {
			throw new Error('no result found');
		}
		$info = $this->connection->getEntries($result);
		if ($info === false) {
			throw new Error('invalid results found');
		}
		return $info;
	}

	/**
	 * This method authenticates the user <var>$username</var> using the
	 * password <var>$password</var>
	 *
	 * @param string $filter OPTIONAL This parameter defines the Filter to be used
	 * when searchin for the username. This MUST contain the string '%s' which
	 * will be replaced by the vaue given in <var>$username</var>
	 * @throws Error
	 */
	public function authenticate(string $username, string $password, string $filter = '(uid=%s)'): bool
	{
		$this->connect();
		$this->bind();
		$res = $this->search(sprintf($filter, $this->factory->escape($username, '', LDAP_ESCAPE_FILTER)));
		if ($res ['count'] !== 1) {
			return false;
		}

		$dn = $res[0]['dn'];
		return $username && $password && $this->connection->bind($dn, $password);
	}
}
