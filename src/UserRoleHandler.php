<?php

declare(strict_types=1);

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdap;

use WP_User;
use function array_search;
use function in_array;

class UserRoleHandler
{
    public function addRolesToUser(WP_User $user, $roles): void
    {
        if (! empty($user->roles)) {
            return;
        }

        if ($user->roles === $roles) {
            return;
        }

        // Remove unused roles from existing.
        foreach ($user->roles as $role) {
            if (!in_array($role, $roles)) {
                // Remove unused roles.
                $user->remove_role($role);
                continue;
            }
            // Remove the existing role from roles.
            if (($key = array_search($role, $roles)) !== false) {
                unset($roles[$key]);
            }
        }

        // Add new ones if not already assigned.
        foreach ($roles as $role) {
            $user->add_role($role);
        }
    }
}
