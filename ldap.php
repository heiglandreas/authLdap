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
class LDAP
{
    private $_server = '';

    private $_scheme = 'ldap';

    private $_port = 389;
	
    private $_baseDn = '';
	
	private $_debug = false;
	/**
	 * This property contains the connection handle to the ldap-server
	 *
	 * @var Ressource
	 */
	private $_ch = null;
	
	private $_username = '';
	
	private $_password = '';
	
	public function __construct($URI, $debug = false)
	{
	    $this->_debug=$debug;
        $url = parse_url ( $URI );
        if ( false === $url ) {
            throw new Exception ( $URI . ' is an invalid URL' );
        }
        if ( ! isset ( $url['scheme'] ) ) {
            throw new Exception ( $URI . ' does not provide a scheme' );
        }
	    if ( 0 !== strpos ( $url['scheme'], 'ldap' ) ) {
            throw new Exception ($URI . ' is an invalid LDAP-URI');
        }
        if ( ! isset ( $url['host'] ) ) {
            throw new Exception ( $URI . ' does not provide a server' );
        }
        if ( ! isset ( $url['path'] ) ) {
            throw new Exception ( $URI . ' does not provide a search-base' );
        }
        if ( 1 == strlen ( $url['path'] ) ) {
            throw new Exception ( $URI . ' does not provide a valid search-base' );
        }
        $this -> _server = $url['host'];
        $this -> _scheme = $url['scheme'];
        $this -> _baseDn = substr($url['path'],1);
        if ( isset ( $url['user'] ) ) {
            $this -> _username = $url['user'];
        }
        if ( '' == trim ( $this -> _username ) ) {
            $this -> _username = 'anonymous';
        }
        if ( isset ( $url['pass'] ) ) {
            $this -> _password = $url['pass'];
        }
        if ( isset ( $url['port'] ) ) {
            $this -> _port = $url['port'];
        }
	}

    /**
     * Connect to the given LDAP-Server
     *
     * @return LDAP
     * @throws AuthLdap_Exception
     */
	public function connect()
	{
        $this -> disconnect ();
        if ( 'ldaps' != $this->_scheme ){
            $this->_ch = @ldap_connect ( $this->_server, $this->_port );
		}else{
			if ( 389 == $this -> _port ) {
				$this -> _port = 636;
			}
			// when URL is used, port is ignored, see http://php.net/manual/en/function.ldap-connect.php
            $this->_ch = @ldap_connect ( $this->_scheme . '://' . $this->_server . ':' . $this -> _port  );
        }
		if ( ! $this->_ch ){
            throw new AuthLDAP_Exception ( 'Could not connect to the server' );
		}
		ldap_set_option($this->_ch, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->_ch, LDAP_OPT_REFERRALS, 0);

		return $this;
	}

    /**
     * Disconnect from a resource if one is available
     *
     * @return LDAP
     */
    public function disconnect()
    {
        if ( is_resource ( $this->_ch ) ) {
            @ldap_unbind ( $this->_ch );
        }
        $this->_ch = null;
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
		if ( ! $this->_ch ){
		    $this->connect();
		}
	    if ( ! is_resource ( $this->_ch ) ) {
            throw new AuthLDAP_Exception('No Resource-handle given');
        }
        $bind = false;
        if ( ( ( $this->_username )
            && ( $this->_username != 'anonymous') )
            && ( $this->_password != '' ) ){
            $bind = @ldap_bind ($this->_ch, $this->_username, $this->_password);
		} else {
            $bind = @ldap_bind($this->_ch);
        }
        if ( ! $bind ){
            throw new AuthLDAP_Exception( 'bind was not successfull' );
    	}
        return $this;
	}
	
	function getErrorNumber()
	{
		return @ldap_errno($this->_ch);
	}
	
	function getErrorText()
	{
		return @ldap_error($this->_ch);
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
	function search( $filter, $attributes = array('uid'))
	{
	    if ( ! is_Resource ( $this->_ch ) ) {
            throw new AuthLDAP_Exception('No resource handle avbailable' );
        }
        $result = @ldap_search ($this->_ch, $this->_baseDn, $filter, $attributes);
        if ( $result === false ){
            throw new AuthLDAP_Exception('no result found');
        }
        $this->_info = @ldap_get_entries ($this->_ch, $result);
        if ( $this->_info === false )
        {
            throw new AuthLDAP_Exception('invalid results found');
        }
        return $this -> _info;
	}
	
	/**
	 * This method sets debugging to ON
	 */
	function debugOn()
	{
		$this->_debug = true;
		return $this;
	}
		
	/**
	 * This method sets debugging to OFF
	 */
	function debugOff()
	{
		$this->_debug = false;
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
	public function authenticate( $username, $password, $filter='(uid=%s)')
	{
	    //return true;
	    $this->connect();
	    $this->bind();
	    $res = $this->search(sprintf($filter, $username));
	    if ( ! $res || ! is_array ( $res ) || ( $res ['count'] != 1 ) ){
	        return false;
	    }
	    $dn = $res[0]['dn'];
	    if ( $username && $password ){
	        if ( @ldap_bind($this->_ch, $dn, $password) ){
	            return true;
	        }
	    }   
	    return false;
	}
	/**
	 * $this method loggs errors if debugging is set to ON
	 */
	function logError()
	{
		if($this->_debug){
		    $_v = debug_backtrace();
		    throw new AuthLDAP_Exception ( '[LDAP_ERROR]' . ldap_errno($this->_ch) . ':' . ldap_error($this->_ch), $_v[0]['line'] );
		}
	}
}

class AuthLDAP_Exception extends Exception
{
    public function __construct ( $message, $line = null)
    {
        parent :: __construct($message);
        if ( $line ){
            $this -> line = $line;
        }
    }
}
