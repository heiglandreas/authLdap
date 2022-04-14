<?php
/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdapTest;

use Org_Heigl\AuthLdap\UserRoleHandler;
use WorDBless\BaseTestCase;
use WP_User;

class UserRoleHandlerTest extends BaseTestCase
{
    public function testUserRolesAreAssignedAsExpected(): void
    {
        $user = new WP_User(1);
        $user->add_role('Administrator');

        $handler = new UserRoleHandler();

        $handler->addRolesToUser($user, ['Author', 'User']);

        self::assertEquals(['Author', 'User'], $user->roles);
    }

}
