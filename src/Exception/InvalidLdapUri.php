<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Exception;

use RuntimeException;

class InvalidLdapUri extends RuntimeException
{
    public static function fromLdapUriString(string $ldapUri): InvalidLdapUri
    {
        return new self('"%s" is not a valid LDAP-URI.');
    }
}
