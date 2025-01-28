<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

use Exception;
use Org_Heigl\AuthLdap\Value\CachePassword;
use Org_Heigl\AuthLdap\Value\DoNotOverwriteNonLdapUsers;
use Org_Heigl\AuthLdap\Value\LoggedInUser;
use Org_Heigl\AuthLdap\Value\MailAttribute;
use Org_Heigl\AuthLdap\Value\NameAttribute;
use Org_Heigl\AuthLdap\Value\ReadLdapAsUser;
use Org_Heigl\AuthLdap\Value\SecondNameAttribute;
use Org_Heigl\AuthLdap\Value\UidAttribute;
use Org_Heigl\AuthLdap\Value\UserFilter;
use Org_Heigl\AuthLdap\Value\WebAttribute;
use UnexpectedValueException;
use WP_User;

final class LoggedInUserToWpUser
{
	private LdapList $backend;

	private LoggerInterface $logger;

	private UserFilter $userFilter;

	private	ReadLdapAsUser $readLdapAsUser;

	private NameAttribute $nameAttribute;

	private SecondNameAttribute $secondNameAttribute;

	private MailAttribute $mailAttribute;

	private UidAttribute $uidAttribute;

	private WebAttribute $webAttribute;

	private DoNotOverwriteNonLdapUsers $doNotOverwriteNonLdapUsers;

	private CachePassword $cachePassword;

	public function __construct(
		LdapList $backend,
		LoggerInterface $logger,
		UserFilter $userFilter,
		ReadLdapAsUser $userRead,
		NameAttribute $nameAttribute,
		SecondNameAttribute $secondNameAttribute,
		MailAttribute $mailAttribute,
		UidAttribute $uidAttribute,
		WebAttribute $webAttribute,
		DoNotOverwriteNonLdapUsers $doNotOverwriteNonLdapUsers,
		CachePassword $cachePassword,
	) {
		$this->backend = $backend;
		$this->logger = $logger;
		$this->userFilter = $userFilter;
		$this->readLdapAsUser = $userRead;
		$this->nameAttribute = $nameAttribute;
		$this->secondNameAttribute = $secondNameAttribute;
		$this->mailAttribute = $mailAttribute;
		$this->uidAttribute = $uidAttribute;
		$this->webAttribute = $webAttribute;
		$this->doNotOverwriteNonLdapUsers = $doNotOverwriteNonLdapUsers;
		$this->cachePassword = $cachePassword;
	}

	/**
	 * @param LoggedInUser $loggedInUser
	 * @return WP_User|false;
	 */
	public function __invoke(LoggedInUser $loggedInUser)
	{
		try {
			// Make optional querying from the admin account #213
			if (! $this->readLdapAsUser->isEnabled()) {
				// Rebind with the default credentials after the user has been loged in
				// Otherwise the credentials of the user trying to login will be used
				// This fixes #55
				$this->logger->log('Rebinding with default credentials');
				$this->backend->bind();
			}

			$attributes = array_values(
				array_filter(
					apply_filters(
						'authLdap_filter_attributes',
						[
							(string)$this->nameAttribute,
							(string)$this->secondNameAttribute,
							(string)$this->mailAttribute,
							(string)$this->webAttribute,
							(string)$this->uidAttribute,
						]
					)
				)
			);

			try {
				$attribs = $this->backend->search(
					sprintf((string)$this->userFilter, $loggedInUser->getUsername()),
					$attributes
				);
				// First get all the relevant group informations so we can see if
				// whether have been changes in group association of the user
				if (!isset($attribs[0]['dn'])) {
					$this->logger->log('could not get user attributes from LDAP');
					throw new UnexpectedValueException('dn has not been returned');
				}
				if (!isset($attribs[0][strtolower((string)$this->uidAttribute)][0])) {
					$this->logger->log('could not get user attributes from LDAP');
					throw new UnexpectedValueException('The user-ID attribute has not been returned');
				}

				$dn = $attribs[0]['dn'];
				$realuid = $attribs[0][strtolower((string)$this->uidAttribute)][0];
			} catch (Exception $e) {
				$this->logger->log('Exception getting LDAP user: ' . $e->getMessage());
				return false;
			}

			// TODO: Refactor
			$uid = authLdap_get_uid($realuid);

			// This fixes #172
			if (true === $this->doNotOverwriteNonLdapUsers->isEnabled()) {
				// TODO: Refactor
				if (get_userdata($uid) && !get_user_meta($uid, 'authLDAP')) {
					return null;
				}
			}

			// now, lets update some user details
			$user_info = [];
			$user_info['user_login'] = $realuid;
			$user_info['user_email'] = '';
			$user_info['user_nicename'] = '';

			// first name
			if (isset($attribs[0][strtolower((string)$this->nameAttribute)][0])) {
				$user_info['first_name'] = $attribs[0][strtolower((string)$this->nameAttribute)][0];
			}

			// last name
			if (isset($attribs[0][strtolower((string)$this->secondNameAttribute)][0])) {
				$user_info['last_name'] = $attribs[0][strtolower((string)$this->secondNameAttribute)][0];
			}

			// mail address
			if (isset($attribs[0][strtolower((string)$this->mailAttribute)][0])) {
				$user_info['user_email'] = $attribs[0][strtolower((string)$this->mailAttribute)][0];
			}

			// website
			if (isset($attribs[0][strtolower((string)$this->webAttribute)][0])) {
				$user_info['user_url'] = $attribs[0][strtolower((string)$this->webAttribute)][0];
			}
			// display name, nickname, nicename
			if (array_key_exists('first_name', $user_info)) {
				$user_info['display_name'] = $user_info['first_name'];
				$user_info['nickname'] = $user_info['first_name'];
				// TODO: Refactor sanitize_title_with_dashes
				$user_info['user_nicename'] = sanitize_title_with_dashes($user_info['first_name']);
				if (array_key_exists('last_name', $user_info)) {
					$user_info['display_name'] .= ' ' . $user_info['last_name'];
					$user_info['nickname'] .= ' ' . $user_info['last_name'];
					// TODO: Refactor sanitize_title_with_dashes
					$user_info['user_nicename'] .= '_' . sanitize_title_with_dashes($user_info['last_name']);
				}
			}
			$user_info['user_nicename'] = substr($user_info['user_nicename'], 0, 50);

			// optionally store the password into the wordpress database
			if ($this->cachePassword->isEnabled()) {
				// Password will be hashed inside wp_update_user or wp_insert_user
				$user_info['user_pass'] = $loggedInUser->getPassword();
			} else {
				// clear the password
				$user_info['user_pass'] = '';
			}

			// add uid if user exists
			if ($uid) {
				// found user in the database
				$this->logger->log('The LDAP user has an entry in the WP-Database');
				$user_info['ID'] = $uid;
				unset($user_info['display_name'], $user_info['nickname']);
				// TODO: Refactor call to wp_update_user
				$userid = wp_update_user($user_info);
			} else {
				// new WordPress account will be created
				$this->logger->log('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');
				// If we do not set an empty role here, the default mechanism of WordPress
				// takes over and adds the default role here.
				// We make sur eto handle that in the Authorize-file later.
				$user_info['role'] = '';
				// TODO: Refactor call to wp_insert_user
				$userid = wp_insert_user($user_info);
			}

			// if the user exists, wp_insert_user will update the existing user record
			if (is_wp_error($userid)) {
				$this->logger->log(sprintf(
					'Error creating user: %s',
					$userid->get_error_message()
				));
				trigger_error(sprintf(
					'Error creating user: %s',
					$userid->get_error_message()
				));
				return false;
			}

			/**
			 * Add hook for custom updates
			 *
			 * @param int $userid User ID.
			 * @param array $attribs [0] Attributes retrieved from LDAP for the user.
			 */
			do_action('authLdap_login_successful', $userid, $attribs[0]);

			$this->logger->log('user id = ' . $userid);

			// flag the user as an ldap user so we can hide the password fields in the user profile
			update_user_meta($userid, 'authLDAP', true);

			return new \WP_User($userid);
		} catch (Exception $exception) {
			$this->logger->log($exception->getMessage());
			return false;
		}
	}
}
