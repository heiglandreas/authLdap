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

namespace Org_Heigl\AuthLdapTest\Manager;

use Org_Heigl\AuthLdap\Exception\Error;
use Org_Heigl\AuthLdap\LdapList;
use Org_Heigl\AuthLdap\LdapUri;
use Org_Heigl\AuthLdap\Manager\Ldap;
use Org_Heigl\AuthLdap\Wrapper\Ldap as LdapWrapper;
use Org_Heigl\AuthLdap\Wrapper\LdapFactory;
use Org_Heigl\AuthLdap\Wrapper\LdapInterface;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class LDAPBaseTest extends TestCase
{
    private LdapFactory $factory;

    private LdapInterface $wrapper;

    public function setUp(): void
    {
        $this->wrapper = $this->getMockBuilder(LdapInterface::class)->getMock();
        $this->factory = $this->getMockBuilder(LdapFactory::class)->getMock();
        $this->factory->method('createFromLdapUri')->willReturn($this->wrapper);
		$this->factory->method('escape')->willReturnCallback(function ($value, $ignore, $flags) {
			return \Org_Heigl\AuthLdap\Wrapper\Ldap::escape($value, $ignore, $flags);
		});
    }

    /**
     * @dataProvider bindingWithPasswordProvider
     * @testdox Binding user $user with password $password using a filter $filter works
     */
    public function testThatBindingWithPasswordWorks($user, $password, $filter, $uri)
    {
		$uri = LdapUri::fromString($uri);
	    $this->wrapper
		    ->method('bind')
		    ->willReturn(true);

		$this->wrapper
			->expects($this->once())
			->method('search')
			->with($uri->getBaseDn(), sprintf($filter, $user));

		$this->wrapper
			->method('getEntries')
			->willReturn(['count' => 1, 0 => ['dn' => 'foo']]);

	    $ldap = new Ldap($this->factory, $uri);
        $this->assertTrue($ldap->authenticate($user, $password, $filter));
    }

    public static function bindingWithPasswordProvider()
    {
        return [
            [
                'user3',
                'user!"',
                'uid=%s',
                'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=example,dc=org'
            ], [
//                'admin',
//                'insecure',
//                'cn=%s',
//                'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=example,dc=org'
//            ], [
                'user1',
                'user1',
                'uid=%s',
                'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=example,dc=org'
            ], [
                'user 4',
                'user!"',
                'uid=%s',
                'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=example,dc=org'
            ], [
                'user 5',
                'user!"',
                'uid=%s',
                'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=test%20space,dc=example,dc=org'
            ],
        ];
    }

    /**
     * @param $uri
     * @dataProvider initialBindingToLdapServerWorksProvider
     */
    public function testThatInitialBindingWorks($uri)
    {
	    $this->wrapper
		    ->method('bind')
		    ->willReturn(true);

	    $ldap = new LDAP($this->factory, LdapUri::fromString($uri));
        $this->assertInstanceof(Ldap::class, $ldap->bind());
    }

    /**
     * @param $uri
     * @dataProvider initialBindingToLdapServerWorksProvider
     */
    public function testThatInitialBindingToMultipleLdapsWorks($uri)
    {
		$this->wrapper->expects($this->once())
	        ->method('bind')
			->with('uid=user 5,dc=test space,dc=example,dc=org', 'user!"')
			->willReturn(true);

        $list = new LdapList();
        $list->addLDAP(new LDAP($this->factory, LdapUri::fromString($uri)));
        $this->assertTrue($list->bind());
    }

    public static function initialBindingToLdapServerWorksProvider()
    {
        return [
            ['ldap://uid=user%205,dc=test%20space,dc=example,dc=org:user!"' .
                '@127.0.0.1:3389/dc=test%20space,dc=example,dc=org'],
        ];
    }

    /**
     * @dataProvider provideUnescapedData
     */
    public function testThatPassedDataIsEscaped($unescaped, $escaped): void
    {
        $ldap = new LDAP($this->factory, LdapUri::fromString(
            'ldap://cn=admin,dc=example,dc=org:insecure@127.0.0.1:3389/dc=example,dc=org'
        ));

		$this->wrapper->expects($this->exactly(2))
			->method('bind')->with(
				['cn=admin,dc=example,dc=org', 'insecure'],
				['foo', 'password']
			)
			->willReturnOnConsecutiveCalls(true, true);
		$this->wrapper->expects($this->once())->method('search')->with(
			'dc=example,dc=org',
			$escaped,
			['uid'],
		);
		$this->wrapper->method('getEntries')->willReturn(['count' => 1, 0 => ['dn' => 'foo']]);

        $ldap->authenticate($unescaped, 'password');
    }

    public static function provideUnescapedData(): array
    {
        return [
            ['\’foobar', '(uid=\5c’foobar)'],
            ['XXX;(&(uid=Admin)(userPassword=A*))', '(uid=XXX;\28&\28uid=Admin\29\28userPassword=A\2a\29\29)'],
        ];
    }


	public function testSettingStartTls(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->expects($this->once())->method('startTls');
		$this->wrapper->method('bind')->willReturn(true);

		$ldap->bind();
	}


	public function testUnsettingConnectionBeforeBinding(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->method('bind')->willReturn(true);
		$this->wrapper->expects($this->once())->method('unbind');

		$ldap->connect();
		$ldap->disconnect();
	}

	public function testErrorIsThrownOnUnsuccessfullBInd(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->method('bind')->willReturn(false);
		$this->expectException(Error::class);

		$ldap->bind();
	}

	public function testFailingSearchThrowsError(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->method('bind')->willReturn(true);
		$this->wrapper->method('search')->willReturn(false);

		$this->expectException(Error::class);
		$this->expectExceptionMessage('no result found');

		$ldap->bind();
		$ldap->search('uid=foo');
	}

	public function testFailingSearchResultFetchingThrowsError(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->method('bind')->willReturn(true);
		$this->wrapper->method('search')->willReturn(true);
		$this->wrapper->method('getEntries')->willReturn(false);

		$this->expectException(Error::class);
		$this->expectExceptionMessage('invalid results found');

		$ldap->bind();
		$ldap->search('uid=foo');
	}

	public function testSearchingWithoutBindingThrowsError(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->expectException(Error::class);
		$this->expectExceptionMessage('No resource handle available');

		$ldap->search('uid=foo');
	}

	public function testAuthenticatingFailsWithNoSearchResults(): void
	{
		$ldap = new Ldap($this->factory, LdapUri::fromString('ldap://example.com/foo=bar'), true);

		$this->wrapper->method('bind')->willReturn(true);
		$this->wrapper->method('search')->willReturn(true);
		$this->wrapper->method('getEntries')->willReturn(['count' => 0]);

		$ldap->bind();
		Assert::assertFalse($ldap->authenticate('foo', 'bar'));
	}
}
