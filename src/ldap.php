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
namespace Org_Heigl\AuthLdap;

use Org_Heigl\AuthLdap\Exception as LdapException;
use Exception;

class LDAP
{
    /** @var string */
    private $server = '';

    /** @var string ldap|ldaps */
    private $scheme = 'ldap';

    /** @var int */
    private $port = 389;

    /** @var string */
    private $baseDn = '';

    /** @var bool */
    private $debug = false;

    /**
     * This property contains the connection handle to the ldap-server
     *
     * @var Ressource
     */
    private $ch = null;

    /** @var string */
    private $username = '';

    /** @var string */
    private $password = '';

    /** @var bool */
    private $starttls = false;

    /**
     * @param string $URI
     * @param bool   $debug
     * @param bool   $starttls
     */
    public function __construct($URI, $debug = false, $starttls = false)
    {
        $this->debug =$debug;
        $array       = parse_url($URI);
        if (! is_array($array)) {
            throw new Exception($URI . ' seems not to be a valid URI');
        }
        $url = array_map(
            function ($item) {
                return urldecode($item);
            },
            $array
        );

        if (false === $url) {
            throw new Exception($URI . ' is an invalid URL');
        }
        if (! isset($url['scheme'])) {
            throw new Exception($URI . ' does not provide a scheme');
        }
        if (0 !== strpos($url['scheme'], 'ldap')) {
            throw new Exception($URI . ' is an invalid LDAP-URI');
        }
        if (! isset($url['host'])) {
            throw new Exception($URI . ' does not provide a server');
        }
        if (! isset($url['path'])) {
            throw new Exception($URI . ' does not provide a search-base');
        }
        if (1 == strlen($url['path'])) {
            throw new Exception($URI . ' does not provide a valid search-base');
        }
        $this -> server = $url['host'];
        $this -> scheme = $url['scheme'];
        $this -> baseDn = substr($url['path'], 1);
        if (isset($url['user'])) {
            $this -> username = $url['user'];
        }
        if ('' == trim($this -> username)) {
            $this -> username = 'anonymous';
        }
        if (isset($url['pass'])) {
            $this -> password = $url['pass'];
        }
        if (isset($url['port'])) {
            $this -> port = $url['port'];
        }
        $this->starttls = $starttls;
    }

    /**
     * Connect to the given LDAP-Server
     *
     * @return LDAP
     * @throws AuthLdap_Exception
     */
    public function connect()
    {
        $this -> disconnect();
        if ('ldaps' == $this->scheme && 389 == $this->port) {
            $this->port = 636;
        }

        $this->ch = @ldap_connect($this->scheme . '://' . $this->server . ':' . $this -> port);
        if (! $this->ch) {
            throw new AuthLDAP_Exception('Could not connect to the server');
        }
        ldap_set_option($this->ch, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->ch, LDAP_OPT_REFERRALS, 0);
        // If configured try to upgrade encryption to tls for ldap connections.
        if ($this->starttls) {
            ldap_start_tls($this->ch);
        }
        return $this;
    }

    /**
     * Disconnect from a resource if one is available
     *
     * @return LDAP
     */
    public function disconnect()
    {
        if (is_resource($this->ch)) {
            @ldap_unbind($this->ch);
        }
        $this->ch = null;
        return $this;
    }

    /**
     * Bind to an LDAP-Server with the given credentials
     *
     * @return LDAP
     * @throw AuthLdap_Exception
     */
    public function bind()
    {
        if (! $this->ch) {
            $this->connect();
        }
        if (! is_resource($this->ch)) {
            throw new LdapException('No Resource-handle given');
        }
        $bind = false;
        if (( ( $this->username )
            && ($this->username != 'anonymous') )
            && ($this->password != '' ) ) {
            $bind = @ldap_bind($this->ch, $this->username, $this->password);
        } else {
            $bind = @ldap_bind($this->ch);
        }
        if (! $bind) {
            throw new LdapException('bind was not successfull: ' . ldap_error($this->ch));
        }
        return $this;
    }

    public function getErrorNumber()
    {
        return @ldap_errno($this->ch);
    }

    public function getErrorText()
    {
        return @ldap_error($this->ch);
    }

    /**
     * This method does the actual ldap-serch.
     *
     * This is using the filter <var>$filter</var> for retrieving the attributes
     * <var>$attributes</var>
     *
     *
     * @param string $filter
     * @param array $attributes
     * @return array
     */
    public function search($filter, $attributes = array('uid'))
    {
        if (! is_Resource($this->ch)) {
            throw new LdapException('No resource handle avbailable');
        }
        $result = @ldap_search($this->ch, $this->baseDn, $filter, $attributes);
        if ($result === false) {
            throw new LdapException('no result found');
        }
        $this->_info = @ldap_get_entries($this->ch, $result);
        if ($this->_info === false) {
            throw new LdapException('invalid results found');
        }
        return $this -> _info;
    }

    /**
     * This method sets debugging to ON
     */
    public function debugOn()
    {
        $this->debug = true;
        return $this;
    }

    /**
     * This method sets debugging to OFF
     */
    public function debugOff()
    {
        $this->debug = false;
        return $this;
    }

    /**
     * This method authenticates the user <var>$username</var> using the
     * password <var>$password</var>
     *
     * @param string $username
     * @param string $password
     * @param string $filter OPTIONAL This parameter defines the Filter to be used
     * when searchin for the username. This MUST contain the string '%s' which
     * will be replaced by the vaue given in <var>$username</var>
     * @return boolean true or false depending on successfull authentication or not
     */
    public function authenticate($username, $password, $filter = '(uid=%s)')
    {
        $this->connect();
        $this->bind();
        $res = $this->search(sprintf($filter, $username));
        if (! $res || ! is_array($res) || ( $res['count'] != 1 )) {
            return false;
        }
        $dn = $res[0]['dn'];
        if ($username && $password) {
            if (@ldap_bind($this->ch, $dn, $password)) {
                return true;
            }
        }
        return false;
    }
    /**
     * This method loggs errors if debugging is set to ON.
     */
    public function logError()
    {
        if ($this->debug) {
            $_v = debug_backtrace();
            throw new LdapException('[LDAP_ERROR]' . ldap_errno($this->ch) . ':' . ldap_error($this->ch), $_v[0]['line']);
        }
    }
}
