<?php

namespace Org_Heigl\AuthLdapTest;

use Generator;
use Org_Heigl\AuthLdap\Exception\InvalidLdapUri;
use Org_Heigl\AuthLdap\LdapUri;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

use function getenv;
use function putenv;

class LdapUriTest extends TestCase
{
	public function toStringProvider(): Generator
	{
		yield ['ldaps://foo:bar@foo.bar/baz', 'ldaps://foo.bar:636', 'foo', 'bar', 'baz'];
		yield ['env:LDAP_URI', 'ldaps://foo.bar:636', 'foo', 'bar', 'baz', [
			'LDAP_URI' => 'ldaps://foo:bar@foo.bar/baz',
		]];
        yield ['ldaps://foo:%env:LDAP_PASSWORD%@foo.bar/baz', 'ldaps://foo.bar:636', 'foo', 'bar', 'baz', [
			'LDAP_PASSWORD' => 'bar',
        ]];
        yield ['ldaps://foo:%env:LDAP_PASSWORD%@foo.bar/baz', 'ldaps://foo.bar:636', 'foo', 'ba r', 'baz', [
	        'LDAP_PASSWORD' => 'ba r',
        ]];
    }

	public function fromStringProvider(): Generator
	{
		yield ['ldaps://foo:bar@foo.bar/baz', false];
		yield ['env:LDAP_URI', false];
		yield ['foo:MyLdapUri', true];
	}

	/**
	 * @dataProvider toStringProvider
	 */
	public function testToString(string $uri, string $result, $user, $password, $baseDn, array $env = []): void
	{
		foreach ($env as $key => $value) {
			putenv("$key=$value");
		}
		$ldapUri = LdapUri::fromString($uri);
		Assert::assertSame($result, $ldapUri->toString());
		Assert::assertSame($user, $ldapUri->getUsername());
		Assert::assertSame($password, $ldapUri->getPassword());
		Assert::assertSame($baseDn, $ldapUri->getBaseDn());
	}

	/** @dataProvider fromStringProvider */
	public function testFromString(string $uri, bool $failure = false): void
	{
		if ($failure) {
			self::expectException(InvalidLdapUri::class);
		}
		$ldapUri = LdapUri::fromString($uri);
		self::assertInstanceOf(LdapUri::class, $ldapUri);
	}

	public function testSettingLdapsWillSetCorrectPort(): void
	{
		$uri = LdapUri::fromString('ldaps://example.org/foo');

		Assert::assertSame('ldaps://example.org:636', $uri->toString());
	}

	public function testSettingLdapWillSetCorrectPort(): void
	{
		$uri = LdapUri::fromString('ldap://example.org/foo');

		Assert::assertSame('ldap://example.org:389', $uri->toString());
	}

	/**
	 * @dataProvider anonymousProvider
	 */
	public function testUriIsAnonymous(string $uri): void
	{
		$uri = LdapUri::fromString($uri);
		Assert::assertTrue($uri->isAnonymous());
	}

	public function anonymousProvider(): Generator
	{
		yield ['ldaps://test.example.com/dc=com'];
		yield ['ldaps://foo@test.example.com/dc=com'];
		yield ['ldaps://%20:password@test.example.com/dc=com'];
		yield ['ldaps://anonymous:password@test.example.com/dc=com'];
	}

	public function testMissingSchemaThrows(): void
	{
		$this->expectException(InvalidLdapUri::class);

		LdapUri::fromString('ldaps.example.com');
	}

	public function testMWrongSchemaThrows(): void
	{
		$this->expectException(InvalidLdapUri::class);

		LdapUri::fromString('environ://ldaps.example.com');
	}

	public function testMissingHostThrows(): void
	{
		$this->expectException(InvalidLdapUri::class);

		LdapUri::fromString('ldaps:/foo=bar');
	}

	public function testgettingUriFromEnvironment(): void
	{
		putenv('URI=ldaps://example.com/foo');
		$uri = LdapUri::fromString('env:URI');

		Assert::assertSame('ldaps://example.com:636', (string) $uri);
		Assert::assertSame('foo', $uri->getBaseDn());
	}

	public function testgettingUriFromEmptyEnvironment(): void
	{
		putenv('URI');
		$this->expectException(InvalidLdapUri::class);
		$uri = LdapUri::fromString('env:URI');
	}
}
