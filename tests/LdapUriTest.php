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
    }

    public function fromStringProvider(): Generator
    {
        yield ['ldaps://foo:bar@foo.bar/baz', false];
    }

    /** @dataProvider toStringProvider */
    public function testToString(string $uri, string $result): void
    {
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
