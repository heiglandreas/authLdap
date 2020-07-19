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

namespace Org_Heigl\AuthLdapTest;

use Exception;
use Generator;
use PHPUnit\Framework\TestCase;
use Org_Heigl\AuthLdap\LDAP;

class LdapTest extends TestCase
{
    /**
     *
     * @dataProvider dpInstantiateLdapClass
     * @param array $expected
     * @param array $given
     */
    public function testInstantiateLdapClass($ldapUri, $debug, $startTls)
    {
        $ldap = new LDAP($ldapUri, $debug, $startTls);
        self::assertInstanceOf(LDAP::class, $ldap);
    }

    /**
     * @dataProvider dpExceptionsWhenInstantiatingLdapClass
     * @param array $expected
     */
    public function testExceptionsWhenInstantiatingLdapClass($expected)
    {
        self::expectException(Exception::class);
        new LDAP($expected);
    }

    public function dpInstantiateLdapClass(): Generator
    {
        yield [
            'ldap://uid=jondoe,cn=users,cn=example,c=org:secret@ldap.example.org/cn=example,c=org',
            true,
            false,
            [
                'username' => 'uid=jondoe,cn=users,cn=example,c=org',
                'password' => 'secret',
                'server'   => 'ldap.example.org',
                'baseDn'   => 'cn=example,c=org',
                'debug'    => true
            ]
        ];
        yield [
            'ldap://uid=jondoe,cn=users,cn=example,c=org@ldap.example.org/cn=example,c=org',
            true,
            false,
            [
                'username' => 'uid=jondoe,cn=users,cn=example,c=org',
                'password' => '',
                'server'   => 'ldap.example.org',
                'baseDn'   => 'cn=example,c=org',
                'debug'    => true
            ]
        ];
        yield [
            'ldap://ldap.example.org/cn=example,c=org',
            true,
            false,
            [
                'username' => 'anonymous',
                'password' => '',
                'server'   => 'ldap.example.org',
                'baseDn'   => 'cn=example,c=org',
                'debug'    => true
            ]
        ];
//      yield [
//           'ldap://ldap.example.org',
//              true,
//              false,
//              [
//                  'username' => 'anonymous',
//                  'password' => '',
//                  'server'   => 'ldap.example.org',
//                  'baseDn'   => '',
//                  'debug'    => true
//             ]
//          ];
        yield [
            'ldap://uid=jondoe,cn=users,cn=example,c=org:secret@ldap.example.org/cn=example,c=org',
            false,
            false,
            [
                'username' => 'uid=jondoe,cn=users,cn=example,c=org',
                'password' => 'secret',
                'server'   => 'ldap.example.org',
                'baseDn'   => 'cn=example,c=org',
                'debug'    => false
            ],
        ];
        yield [
            'ldap://ldap.example.org/cn=test%20example,c=org',
            false,
            false,
            [
                'username' => 'anonymous',
                'password' => '',
                'server'   => 'ldap.example.org',
                'baseDn'   => 'cn=test example,c=org',
                'debug'    => false
             ]
        ];
    }

    public function dpExceptionsWhenInstantiatingLdapClass(): Generator
    {
        yield ['ldap://ldap.example.org'];
        yield ['ldap://foo:bar@/cn=example,c=org'];
        yield ['http://ldap.example.org'];
        yield ['fooBar'];
        yield ['ldap://ldap.example.org/'];
        yield ['()123üäö'];
    }

    public function testThatGroupMappingWorks()
    {
        $groups = [
            'count' => 1,
            0 => [
                'dn' => 'dn-1',
                'count' => 1,
                0 => 'group',
                'group' => [
                    'count' => 2,
                    0 => '7310T270:Překladatelství:čeština - angličtina@ff.cuni.cz',
                    1 => '7310T033:Český jazyk a literatura@ff.cuni.cz',
                ]
            ]
        ];

        $grp = array();
        for ($i = 0; $i < $groups ['count']; $i++) {
            for ($k = 0; $k < $groups[$i][strtolower('group')]['count']; $k++) {
                $grp[] = $groups[$i][strtolower('group')][$k];
            }
        }

        $this->assertEquals([
            '7310T270:Překladatelství:čeština - angličtina@ff.cuni.cz',
            '7310T033:Český jazyk a literatura@ff.cuni.cz',
        ], $grp);

        $role = '';
        foreach (['testrole' => '7310T031:Český jazyk a literatura@ff.cuni.cz,7310T033:Český jazyk a literatura@ff.cuni.cz'] as $key => $val) {
            $currentGroup = explode(',', $val);
            // Remove whitespaces around the group-ID
            $currentGroup = array_map('trim', $currentGroup);
            if (0 < count(array_intersect($currentGroup, $grp))) {
                $role = $key;
                break;
            }
        }

        $this->assertEquals('testrole', $role);
    }
}
