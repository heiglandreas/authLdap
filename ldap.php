<?php
/**
 * $Id$
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
	/**
	 * This constant declares the regex-Pattern to use when parsing a 
	 * UniforRessourceLocator
	 * 
	 * The following parts are declared in the resulting images:
	 * scheme => Index 1
	 * username => index 3
	 * password => index 5
	 * server   => index 6
	 * path     => index 8
	 * params   => index 10
	 * anchor   => index 12
	 */
    const URI_REGEX = '/(\w+)\:\/\/(([a-zA-Z0-9]+)(:([^\:\@]+))?@)?([^\/]+)((\/[^#]*)?(#(.*))?)/';
    
    private $server = '';
	
    private $baseDn = '';
	
	private $debug = false;
	/**
	 * This property contains the connection handle to the ldap-server
	 *
	 * @var Ressource
	 */
	private $ch = false;
	
	private $username = '';
	
	private $password = '';
	
	public function __construct($URI, $debug = false)
	{
	    $this->debug=$debug;
	    if ( preg_match(LDAP::URI_REGEX,$URI,$result)){
	        if ( 'ldap' != $result [1]){
	            throw new Exception ($URI . ' is an invalid LDAP-URI');
	            return false;
	        }
	        $this->server   = $result [6];
	        $this->username = $result [3];
	        $this->password = $result [5];
	        $this->baseDn   = substr($result [8],1);
	    } else
	    {
	        throw new Exception($URI . ' is an invalid URI');
	        return false;
	    }
	}
	
	public function connect()
	{
		$this->ch = @ldap_connect($this->server);
		if ( ! $this->ch ){
		    $this->logError();
		    $this->ch=false;
		    return false;
		}
		return true;
	}
	
	public function bind()
	{
		if ( ! $this->ch ){
		    $this->connect();
		}
	    if($this->ch){
		    $bind = false;
		    if ( ( ( $this->username ) 
		        && ( $this->username != 'anonymous') )
		      && ( $this->dn_passwd != '' ) ){
		        $bind = @ldap_bind ($this->ch, $this->dn, $this->dn_passwd);
		    } else {
		        $bind = @ldap_bind($this->ch);
		    }
		    if ( ! $bind ){
    			$this->logError();
    		    return false;
    		}
			return true;
		}
		return false;
	}
	
	function getErrorNumber()
	{
		return @ldap_errno($this->ch);
	}
	
	function getErrorText()
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
	 * @return array The result array
	 */
	function search( $filter, $attributes = array('uid'))
	{
	    if ($this->ch){
	        $result = @ldap_search ($this->ch, $this->baseDn, $filter, $attributes);
		    if ( $result === false ){
		        $this->logError();
		        return false;
		    }
			$this->info = @ldap_get_entries ($this->ch, $result);
			if ( $this->info === false )
			{
			    $this->logError();
			    return false;
			}
			return $this->info;
		}
		throw new AuthLDAP_Exception ('keine Verbindung');
	}
	
	/**
	 * This method sets debugging to ON
	 */
	function debugOn()
	{
		$this->debug = true;
		return $this;
	}
		
	/**
	 * This method sets debugging to OFF
	 */
	function debugOff()
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
	        if ( @ldap_bind($this->ch, $dn, $password) ){
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
		if($this->debug){
		    $_v = debug_backtrace();
		    throw new AuthLDAP_Exception ( '[LDAP_ERROR]' . ldap_errno($this->ch) . ':' . ldap_error($this->ch), $_v[0]['line'] );
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