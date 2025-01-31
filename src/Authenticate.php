<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

use Exception;
use Org_Heigl\AuthLdap\Value\LoggedInUser;
use Org_Heigl\AuthLdap\Value\Password;
use Org_Heigl\AuthLdap\Value\UserFilter;
use Org_Heigl\AuthLdap\Value\Username;
use WP_Error;
use WP_User;

final class Authenticate
{
	private UserFilter $filter;

	private LdapList $backend;
	private LoggerInterface $logger;
	public function __construct(UserFilter $filter, LdapList $backend, LoggerInterface $logger)
	{
		$this->filter = $filter;
		$this->backend = $backend;
		$this->logger = $logger;
	}

	/**
	 * @param null|WP_User|WP_Error
	 * @param string $username
	 * @param string $password
	 * @return WP_User|WP_Error|LoggedInUser|false
	 */
	public function __invoke(
		$user,
		$username,
		#[\SensitiveParameter]
		$password
	) {
		// If the user has already been authenticated (only in that case we get a
		// WP_User-Object as $user) we skip LDAP-authentication and simply return
		// the existing user-object
		if ($user instanceof WP_User) {
			$this->logger->log(sprintf(
				'User %s has already been authenticated - skipping LDAP-Authentication',
				$user->get('nickname')
			));
			return $user;
		}

		$this->logger->log(sprintf(
			'User "%s" logging in',
			$username
		));

		try {
			$username = Username::fromMixed($username);
		} catch (\InvalidArgumentException $e) {
			$this->logger->log($e->getMessage());

			return false;
		}

		try {
			$password = Password::fromMixed($password);
		} catch (\InvalidArgumentException $e) {
			$this->logger->log($e->getMessage());
			return false;
		}

		try {
			$this->logger->log('about to do LDAP authentication');
			if ($this->backend->Authenticate((string) $username, (string) $password, (string) $this->filter)) {
				$this->logger->log('LDAP authentication successful');
				return LoggedInUser::fromUsernameAndPassword($username, $password);
			}
		} catch (Exception $e) {
			$this->logger->log(sprintf(
				'LDAP authentication failed with exception: %s',
				$e->getMessage()
			));
			return false;
		}

		$this->logger->log('LDAP authentication failed');
		return false;
	}
}
