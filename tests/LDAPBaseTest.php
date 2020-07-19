<?php

/**
 * Copyright (c) 2016-2016} Andreas Heigl<andreas@heigl.org>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Andreas Heigl<andreas@heigl.org>
 * @copyright 2016-2016 Andreas Heigl
 * @license   http://www.opensource.org/licenses/mit-license.php MIT-License
 * @version   0.0
 * @since     07.06.2016
 * @link      http://github.com/heiglandreas/authLDAP
 */
namespace Org_Heigl\AuthLdapTest;

use Org_Heigl\AuthLdap\LDAP;
use Org_Heigl\AuthLdap\LdapList;
use phpmock\spy\Spy;
use PHPUnit\Framework\TestCase;

class LDAPBaseTest extends TestCase
{
    /** @var Spy */
    private $ldap_connect_spy;

    public function setUp(): void
    {
        $this->ldap_connect_spy = new Spy('Org_Heigl\AuthLdap', 'ldap_connect');
        $this->ldap_connect_spy->enable();
    }

    public function tearDown(): void
    {
        $this->ldap_connect_spy->disable();
    }
    /** @dataProvider bindingWithPasswordProvider */
    public function testThatBindingWithPasswordWorks($user, $password, $filter, $uri)
    {
        $ldap = new LDAP($uri);
        $this->assertTrue($ldap->authenticate($user, $password, $filter));
    }

    public function bindingWithPasswordProvider()
    {
        return [
            ['user3', 'user!"', 'uid=%s', 'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org'],
            ['admin', 'insecure', 'cn=%s', 'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org'],
            ['user1', 'user1', 'uid=%s', 'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org'],
            ['user 4', 'user!"', 'uid=%s', 'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org'],
            ['user 5', 'user!"', 'uid=%s', 'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=test%20space,dc=example,dc=org'],
        ];
    }

    /**
     * @param $uri
     * @dataProvider initialBindingToLdapServerWorksProvider
     */
    public function testThatInitialBindingWorks($uri)
    {
        $ldap = new LDAP($uri);
        $this->assertInstanceof(LDAP::class, $ldap->bind());
    }

    /**
     * @param $uri
     * @dataProvider initialBindingToLdapServerWorksProvider
     */
    public function testThatInitialBindingToMultipleLdapsWorks($uri)
    {
        $list = new LdapList();
        $list->addLDAP(new LDAP($uri));
        $this->assertTrue($list->bind());
    }

    public function initialBindingToLdapServerWorksProvider()
    {
        return [
            ['ldap://uid=user%205,dc=test%20space,dc=example,dc=org:user!"@localhost:389/dc=test%20space,dc=example,dc=org'],
        ];
    }

    /** @dataProvider bindingWithPasswordProvider */
    public function testThatBindingWithAddedSlashesFailsWorks($user, $password, $filter)
    {
        $newpassword = addslashes($password);
        $ldap = new LDAP('ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org');
        if ($newpassword === $password) {
            $this->assertTrue($ldap->authenticate($user, $password, $filter));
        } else {
            $this->assertFalse($ldap->authenticate($user, $newpassword, $filter));
        }
    }

    /** @dataProvider serchingForGroupsProvider */
    public function testThatSearchingForGoupsWorks($filter, $user, $groups)
    {
        // (&(objectCategory=group)(member=<USER_DN>))
        $ldap = new LDAP('ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:389/dc=example,dc=org');
        $ldap->bind();
        $this->assertContains($groups, $ldap->search(sprintf($filter, $user), ['cn'])[0]);

    }

    public function serchingForGroupsProvider()
    {
        return [
            [
                '(&(objectclass=groupOfUniqueNames)(uniqueMember=%s))',
                'uid=user 4,dc=example,dc=org',
                ['count' => 1, 0 => 'group4'],
            ],
        ];
    }

    public function testThatSettingLDAPSActuallyGivesTheCorrectPort()
    {

        $ldap = new LDAP('ldaps://cn=admin,dc=example,dc=org:insecure@127.0.0.1/dc=example,dc=org');
        $ldap->connect();

        $this->assertEquals('ldaps://127.0.0.1:636', $this->ldap_connect_spy->getInvocations()[0]->getArguments()[0]);
    }
}
