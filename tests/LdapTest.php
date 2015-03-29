<?php
/**
 * $Id: LdapTest.php 292156 2010-09-21 19:32:01Z heiglandreas $
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
 * This file tests the basic LDAP-Tasks
 *
 * @category authLdap
 * @package authLdap
 * @subpackage UnitTests
 * @author Andreas Heigl<andreas@heigl.org>
 * @copyright 2010 Andreas Heigl<andreas@heigl.org>
 * @license GPL
 * @since 21.09.2010
 */

/** ldap */
require_once 'ldap.php';

class LdapTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @dataProvider dpInstantiateLdapClass
     * @param array $expected
     * @param array $given
     */
    public function testInstantiateLdapClass($expected, $given)
    {
        $ldap = new LDAP($expected[0],$expected[1]);
        foreach ( $given as $key=>$value ) {
            $this -> assertAttributeEquals($value,'_' . $key,$ldap);
        }
    }

    /**
     * @dataProvider dpExceptionsWhenInstantiatingLdapClass
     * @expectedException Exception
     * @param array $expected
     */
    public function testExceptionsWhenInstantiatingLdapClass($expected)
    {
        new LDAP ( $expected );
    }

    public function dpInstantiateLdapClass()
    {
        return array (
            array (
             array ('ldap://uid=jondoe,cn=users,cn=example,c=org:secret@ldap.example.org/cn=example,c=org', true),
             array (
              'username' => 'uid=jondoe,cn=users,cn=example,c=org',
              'password' => 'secret',
              'server'   => 'ldap.example.org',
              'baseDn'   => 'cn=example,c=org',
              'debug'    => true
             )
            ),
            array (
             array ('ldap://uid=jondoe,cn=users,cn=example,c=org@ldap.example.org/cn=example,c=org', true),
             array (
              'username' => 'uid=jondoe,cn=users,cn=example,c=org',
              'password' => '',
              'server'   => 'ldap.example.org',
              'baseDn'   => 'cn=example,c=org',
              'debug'    => true
             )
            ),
            array(
             array ('ldap://ldap.example.org/cn=example,c=org', true),
             array (
              'username' => 'anonymous',
              'password' => '',
              'server'   => 'ldap.example.org',
              'baseDn'   => 'cn=example,c=org',
              'debug'    => true
             )
            ),
//            array(
//             array ('ldap://ldap.example.org', true),
//             array (
//              'username' => 'anonymous',
//              'password' => '',
//              'server'   => 'ldap.example.org',
//              'baseDn'   => '',
//              'debug'    => true
//             )
//            ),
            array(
             array ('ldap://uid=jondoe,cn=users,cn=example,c=org:secret@ldap.example.org/cn=example,c=org', false),
             array (
              'username' => 'uid=jondoe,cn=users,cn=example,c=org',
              'password' => 'secret',
              'server'   => 'ldap.example.org',
              'baseDn'   => 'cn=example,c=org',
              'debug'    => false
             )
            ),
        );
    }

    public function dpExceptionsWhenInstantiatingLdapClass ()
    {
        return array (
                array('ldap://ldap.example.org'),
                array('ldap://foo:bar@/cn=example,c=org'),
                array('http://ldap.example.org'),
                array('fooBar'),
                array('ldap://ldap.example.org/'),
                array('()123üäö'),
               );
    }
}