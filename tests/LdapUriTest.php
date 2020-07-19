<?php

namespace Org_Heigl\AuthLdapTest;

use Generator;
use Org_Heigl\AuthLdap\Exception\InvalidLdapUri;
use Org_Heigl\AuthLdap\LdapUri;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class LdapUriTest extends TestCase
{
    public function toStringProvider(): Generator
    {
        yield ['ldaps://foo:bar@foo.bar/baz', 'ldaps://foo:bar@foo.bar/baz'];
        yield ['env:LDAP_URI', 'ldaps://foo:bar@foo.bar/baz', [
            'LDAP_URI' => 'ldaps://foo:bar@foo.bar/baz'
        ]];
        yield ['ldaps://foo:%env:LDAP_PASSWORD%@foo.bar/baz', 'ldaps://foo:bar@foo.bar/baz', [
            'LDAP_PASSWORD' => 'bar'
        ]];
        yield ['ldaps://foo:%env:LDAP_PASSWORD%@foo.bar/baz', 'ldaps://foo:ba%20r@foo.bar/baz', [
            'LDAP_PASSWORD' => 'ba r'
        ]];
    }

    public function fromStringProvider(): Generator
    {
        yield ['ldaps://foo:bar@foo.bar/baz', false];
        yield ['env:LDAP_URI', false];
        yield ['foo:MyLdapUri', true];
    }

    /** @dataProvider toStringProvider */
    public function testToString(string $uri, string $result, array $env = []): void
    {
        foreach ($env as $key => $value) {
            putenv("$key=$value");
        }
        $ldapUri = LdapUri::fromString($uri);
        Assert::assertSame($result, $ldapUri->toString());
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
}
