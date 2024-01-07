<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdapTest;

use Org_Heigl\AuthLdap\UserRoleHandler;
use PHPUnit\Framework\TestCase;
use WP_User;

class UserRoleHandlerTest extends TestCase
{
	public function testUserRolesAreAssignedAsExpected(): void
	{
		$user = new WP_User(1);

		$handler = new UserRoleHandler();

		$handler->addRolesToUser($user, ['author', 'user']);

		self::assertEquals(['author'], $user->roles);
	}

	public function testEqualUserRolesAreEasy(): void
	{
		$user = new WP_User(1);
		$user->add_role('administrator');
		$user->add_role('author');

		$handler = new UserRoleHandler();

		$handler->addRolesToUser($user, ['administrator', 'author']);

		self::assertEquals(['administrator', 'author'], $user->roles);
	}

	public function testUserRolesAreNotAssignedWhenUserAlreadyHasRole(): void
	{
		$user = new WP_User(1);
		$user->add_role('administrator');
		$user->add_role('author');

		$handler = new UserRoleHandler();

		$handler->addRolesToUser($user, ['author', 'editor']);

		self::assertEquals(['author', 'editor'], $user->roles);
	}

	public function testEmptyRolesAreIgnored(): void
	{
		$user = new WP_User(1);
		$user->add_role('administrator');

		$handler = new UserRoleHandler();
		$handler->addRolesToUser($user, []);

		self::assertEquals(['administrator'], $user->roles);
	}
}
