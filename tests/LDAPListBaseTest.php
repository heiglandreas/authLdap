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
use PHPUnit_Framework_TestCase;

class LDAPListBaseTest extends PHPUnit_Framework_TestCase
{
    /** @dataProvider bindingWithPasswordProvider */
    public function testThatBindingWithPasswordWorks($user, $password, $filter)
    {
        require_once __DIR__ . '/../src/LdapList.php';
        $ldaplist = new \Org_Heigl\AuthLdap\LdapList();
        $ldaplist->addLdap(new LDAP('ldap://cn=Manager,dc=example,dc=com:insecure@127.0.0.1:3890/dc=example,dc=com'));
        $this->assertTrue($ldaplist->authenticate($user, $password, $filter));
    }

    public function bindingWithPasswordProvider()
    {
        return [
                [
                 'user3',
                 'user!"',
                 'uid=%s',
                ],
                [
                 'Manager',
                 'insecure',
                 'cn=%s',
                ],
                [
                 'user1',
                 'user1',
                 'uid=%s',
                ],
               ];
    }

    /** @dataProvider bindingWithPasswordProvider */
    public function testThatBindingWithAddedSlashesFailsWorks($user, $password, $filter)
    {
        $newpassword = addslashes($password);
        require_once __DIR__ . '/../src/LdapList.php';
        $ldaplist = new \Org_Heigl\AuthLdap\LdapList();
        $ldaplist->addLdap(new LDAP('ldap://cn=Manager,dc=example,dc=com:insecure@127.0.0.1:3890/dc=example,dc=com'));
        if ($newpassword === $password) {
            $this->assertTrue($ldaplist->authenticate($user, $password, $filter));
        } else {
            $this->assertFalse($ldaplist->authenticate($user, $newpassword, $filter));
        }
    }
}
