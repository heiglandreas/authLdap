<?php declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

use Exception;
use Org_Heigl\AuthLdap\Value\DefaultRole;
use Org_Heigl\AuthLdap\Value\GroupAttribute;
use Org_Heigl\AuthLdap\Value\GroupBase;
use Org_Heigl\AuthLdap\Value\GroupEnabled;
use Org_Heigl\AuthLdap\Value\GroupFilter;
use Org_Heigl\AuthLdap\Value\GroupOverUser;
use Org_Heigl\AuthLdap\Value\Groups;
use Org_Heigl\AuthLdap\Value\GroupSeparator;
use Org_Heigl\AuthLdap\Value\UidAttribute;
use Org_Heigl\AuthLdap\Value\UserFilter;
use WP_Roles;
use WP_User;

final class Authorize
{
	private LdapList $backend;

	private LoggerInterface $logger;

	private GroupOverUser $groupOverUser;

	private GroupEnabled $groupEnabled;

	private DefaultRole $defaultRole;

	private UserFilter $userFilter;

	private GroupFilter $groupFilter;

	private GroupAttribute $groupAttribute;

	private GroupBase $groupBase;

	private GroupSeparator $groupSeparator;

	private Groups $groups;

	private UidAttribute $uidAttribute;

	public function __construct(
		LdapList $backend,
		LoggerInterface $logger,
		GroupOverUser $groupOverUser,
		GroupEnabled $groupEnabled,
		DefaultRole $defaultRole,
		UserFilter $userFilter,
		GroupFilter $groupFilter,
		GroupAttribute $groupAttribute,
		GroupBase $groupBase,
		GroupSeparator $groupSeparator,
		Groups $groups,
		UidAttribute $uidAttribute
	) {
		$this->backend = $backend;
		$this->logger = $logger;
		$this->groupOverUser = $groupOverUser;
		$this->groupEnabled = $groupEnabled;
		$this->defaultRole = $defaultRole;
		$this->userFilter = $userFilter;
		$this->groupFilter = $groupFilter;
		$this->groupAttribute = $groupAttribute;
		$this->groupBase = $groupBase;
		$this->groupSeparator = $groupSeparator;
		$this->groups = $groups;
		$this->uidAttribute = $uidAttribute;
	}

	/**
	 * @param WP_User $user
	 * @return false|\WP_Error|WP_User
	 */
	public function __invoke(\WP_User $user)
	{
		try {
			$roles = [];

			// we only need this if either LDAP groups are disabled or
			// if the WordPress role of the user overrides LDAP groups
			if ($this->groupEnabled->isEnabled() === false || $this->groupOverUser->isEnabled() === false) {
				$userRoles = $this->authLdap_user_role($user->ID);
				if ($userRoles !== []) {
					$roles = array_merge($roles, $userRoles);
				}
				// TODO, this needs to be revised, it seems, like authldap is taking only the first role
				// even if in WP there are assigned multiple.
			}

			// do LDAP group mapping if needed
			// (if LDAP groups override wordpress user role, $role is still empty)
			if (($roles === [] || $this->groupOverUser->isEnabled() === true) && $this->groupEnabled->isEnabled() === true) {
				// FIXME: add correct parameters
				$userInfoLdap = $this->backend->search(sprintf(
					(string) $this->userFilter,
					$user->user_login,
				), [(string) $this->uidAttribute, 'dn']);
				if ($userInfoLdap === []) {
					$this->logger->log('Retrieving userinfo again failed');
				}
				$mappedRoles = $this->authLdap_groupmap($userInfoLdap[0][(string) $this->uidAttribute][0], $userInfoLdap[0]['dn']);
				if ($mappedRoles !== []) {
					$roles = $mappedRoles;
					$this->logger->log('role from group mapping: ' . json_encode($roles));
				}
			}

			// if we don't have a role yet, use default role
			if ($roles === [] && (string)$this->defaultRole !== '') {
				$this->logger->log('no role yet, set default role');
				$roles[] = (string) $this->defaultRole;
			}

			if ($roles === []) {
				// Sorry, but you are not in any group that is allowed access
				trigger_error('no group found');
				$this->logger->log('user is not in any group that is allowed access');
				return false;
			}

			$wp_roles = new WP_Roles();
			// not sure if this is needed, but it can't hurt

			// Get rid of unexisting roles.
			foreach ($roles as $k => $v) {
				if (!$wp_roles->is_role($v)) {
					unset($k);
				}
			}

			// check if single role or an empty array provided
			if ($roles === []) {
				trigger_error('no group found');
				$this->logger->log('role is invalid');
				return false;
			}

			/**
			 * Add hook for custom User-Role assignment
			 *
			 * @param WP_User $user This user-object will be returned. Can be modified as necessary in the actions.
			 * @param array $roles
			 */
			do_action('authldap_user_roles', $user, $roles);

		} catch (Exception $e) {
			$this->logger->log($e->getMessage());
			return false;
		}

		return $user;
	}

	/**
	 * Get LDAP groups for user and map to role
	 *
	 * @param string $username
	 * @param string $dn
	 * @return array role, empty array if no mapping found, first or all role(s) found otherwise
	 * @conf array authLDAPGroups, associative array, role => ldap_group
	 * @conf string authLDAPGroupBase, base dn to look up groups
	 * @conf string authLDAPGroupAttr, ldap attribute that holds name of group
	 * @conf string authLDAPGroupFilter, LDAP filter to find groups. can contain %s and %dn% placeholders
	 */
	private function authLdap_groupmap($username, $dn)
	{
		$authLDAPGroups = $this->sortRolesByCapabilities(
			$this->groups
		);

		if (array_filter(array_values($authLDAPGroups)) === []) {
			$this->logger->log('No group names defined');
			return [];
		}

		try {
			// To allow searches based on the DN instead of the uid, we replace the
			// string %dn% with the users DN.
			$this->groupFilter = $this->groupFilter->withDn($dn);

			$this->logger->log(sprintf(
				'Group Filter: %s',
				$this->groupFilter
			));
			$this->logger->log(sprintf(
				'Group Base: %s',
				$this->groupBase
			));

			$groups = $this->backend->search(sprintf(
				(string) $this->groupFilter,
				ldap_escape($username, '', LDAP_ESCAPE_FILTER)
			), [(string) $this->groupAttribute], $this->groupBase);
		} catch (Exception $e) {
			$this->logger->log(sprintf(
				'Exception getting LDAP group attributes: %s',
				$e->getMessage()
			));
			return [];
		}

		$grp = [];
		for ($i = 0; $i < $groups ['count']; $i++) {
			if ((string) $this->groupAttribute === "dn") {
				$grp[] = $groups[$i]['dn'];
			} else {
				for ($k = 0; $k < $groups[$i][(string) $this->groupAttribute]['count']; $k++) {
					$grp[] = $groups[$i][(string) $this->groupAttribute][$k];
				}
			}
		}

		$this->logger->log('LDAP groups: ' . json_encode($grp));

		// Check whether the user is member of one of the groups that are
		// allowed acces to the blog. If the user is not member of one of
		// The groups throw her out! ;-)
		$roles = [];
		foreach ($authLDAPGroups as $key => $val) {
			$currentGroup = explode((string) $this->groupSeparator, $val);
			// Remove whitespaces around the group-ID
			$currentGroup = array_map('trim', $currentGroup);
			if (0 < count(array_intersect($currentGroup, $grp))) {
				$roles[] = $key;
			}
		}

		// Default: If the user is member of more than one group only the first one
		// will be taken into account!
		// This filter allows you to return multiple user roles. WordPress
		// supports this functionality, but not natively via UI from Users
		// overview (you need to use a plugin). However, it's still widely used,
		// for example, by WooCommerce, etc. Use if you know what you're doing.
		if (apply_filters('authLdap_allow_multiple_roles', false) === false && $roles !== []) {
			$roles = array_slice($roles, 0, 1);
		}

		$this->logger->log(sprintf(
			'Roles from LDAP group: %s',
			json_encode($roles)
		));

		return $roles;
	}


	/**
	 * Get the user's current role
	 *
	 * Returns empty string if not found.
	 *
	 * @param int $uid wordpress user id
	 * @return array roles, empty if none found
	 */
	private function authLdap_user_role($uid)
	{
		global $wpdb, $wp_roles;

		if (!$uid) {
			return [];
		}

		/** @var array<string, bool> $usercapabilities */
		$usercapabilities = get_user_meta($uid, "{$wpdb->prefix}capabilities", true);
		if (!is_array($usercapabilities)) {
			return [];
		}

		/** @var array<string, array{name: string, capabilities: array<mixed>} $editable_roles */
		$editable_roles = $wp_roles->roles;

		// By using this approach we are now using the order of the roles from the WP_Roles object
		// and not from the capabilities any more.
		$userroles = array_keys(array_intersect_key($editable_roles, $usercapabilities));

		$this->logger->log(sprintf(
			"Existing user's roles: %s",
			implode(', ', $userroles)
		));

		return $userroles;
	}


	/**
	 * Sort the given roles by number of capabilities
	 *
	 * @param array $groups
	 *
	 * @return array
	 */
	private function sortRolesByCapabilities(Groups $groups): array
	{
		global $wpdb;
		$myRoles = get_option($wpdb->get_blog_prefix() . 'user_roles');

		uasort($myRoles, function ($a, $b): int {
			return count($b['capabilities']) <=> count($a['capabilities']);
		});

		$return = [];

		foreach ($myRoles as $key => $role) {
			if ($groups->has($key)) {
				$return[$key] = $groups->get($key);
			}
		}

		$this->logger->log(print_r($return, true));

		return $return;
	}
}
