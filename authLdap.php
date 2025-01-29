<?php

/*
Plugin Name: AuthLDAP
Plugin URI: https://github.com/heiglandreas/authLdap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 3.0.0
Author: Andreas Heigl <andreas@heigl.org>
Author URI: http://andreas.heigl.org
License: MIT
License URI: https://opensource.org/licenses/MIT
*/

// phpcs:disable PSR1.Files.SideEffects

use Org_Heigl\AuthLdap\Authenticate;
use Org_Heigl\AuthLdap\Authorize;
use Org_Heigl\AuthLdap\LdapList;
use Org_Heigl\AuthLdap\LdapUri;
use Org_Heigl\AuthLdap\LoggedInUserToWpUser;
use Org_Heigl\AuthLdap\Logger;
use Org_Heigl\AuthLdap\Manager\Ldap;
use Org_Heigl\AuthLdap\UserRoleHandler;
use Org_Heigl\AuthLdap\Value\CachePassword;
use Org_Heigl\AuthLdap\Value\DefaultRole;
use Org_Heigl\AuthLdap\Value\DoNotOverwriteNonLdapUsers;
use Org_Heigl\AuthLdap\Value\GroupAttribute;
use Org_Heigl\AuthLdap\Value\GroupBase;
use Org_Heigl\AuthLdap\Value\GroupEnabled;
use Org_Heigl\AuthLdap\Value\GroupFilter;
use Org_Heigl\AuthLdap\Value\GroupOverUser;
use Org_Heigl\AuthLdap\Value\Groups;
use Org_Heigl\AuthLdap\Value\GroupSeparator;
use Org_Heigl\AuthLdap\Value\LoggedInUser;
use Org_Heigl\AuthLdap\Value\MailAttribute;
use Org_Heigl\AuthLdap\Value\NameAttribute;
use Org_Heigl\AuthLdap\Value\ReadLdapAsUser;
use Org_Heigl\AuthLdap\Value\SecondNameAttribute;
use Org_Heigl\AuthLdap\Value\UidAttribute;
use Org_Heigl\AuthLdap\Value\UserFilter;
use Org_Heigl\AuthLdap\Value\WebAttribute;
use Org_Heigl\AuthLdap\Wrapper\LdapFactory;

require_once __DIR__ . '/src/Wrapper/LdapInterface.php';
require_once __DIR__ . '/src/Exception/Error.php';
require_once __DIR__ . '/src/Exception/InvalidLdapUri.php';
require_once __DIR__ . '/src/Exception/Error.php';
require_once __DIR__ . '/src/Exception/InvalidLdapUri.php';
require_once __DIR__ . '/src/Exception/MissingValidLdapConnection.php';
require_once __DIR__ . '/src/Exception/SearchUnsuccessfull.php';
require_once __DIR__ . '/src/Manager/Ldap.php';
require_once __DIR__ . '/src/Wrapper/Ldap.php';
require_once __DIR__ . '/src/Wrapper/LdapFactory.php';
require_once __DIR__ . '/src/LdapList.php';
require_once __DIR__ . '/src/LdapUri.php';
require_once __DIR__ . '/src/UserRoleHandler.php';
require_once __DIR__ . '/src/Value/UserFilter.php';
require_once __DIR__ . '/src/Value/LoggedInUser.php';
require_once __DIR__ . '/src/Value/CachePassword.php';
require_once __DIR__ . '/src/Value/DefaultRole.php';
require_once __DIR__ . '/src/Value/DoNotOverwriteNonLdapUsers.php';
require_once __DIR__ . '/src/Value/Enabled.php';
require_once __DIR__ . '/src/Value/GroupAttribute.php';
require_once __DIR__ . '/src/Value/GroupBase.php';
require_once __DIR__ . '/src/Value/GroupEnabled.php';
require_once __DIR__ . '/src/Value/GroupFilter.php';
require_once __DIR__ . '/src/Value/GroupOverUser.php';
require_once __DIR__ . '/src/Value/Groups.php';
require_once __DIR__ . '/src/Value/GroupSeparator.php';
require_once __DIR__ . '/src/Value/MailAttribute.php';
require_once __DIR__ . '/src/Value/NameAttribute.php';
require_once __DIR__ . '/src/Value/Password.php';
require_once __DIR__ . '/src/Value/ReadLdapAsUser.php';
require_once __DIR__ . '/src/Value/SecondNameAttribute.php';
require_once __DIR__ . '/src/Value/UidAttribute.php';
require_once __DIR__ . '/src/Value/Username.php';
require_once __DIR__ . '/src/Value/WebAttribute.php';
require_once __DIR__ . '/src/Authenticate.php';
require_once __DIR__ . '/src/Authorize.php';
require_once __DIR__ . '/src/LoggedInUserToWpUser.php';
require_once __DIR__ . '/src/LoggerInterface.php';
require_once __DIR__ . '/src/Logger.php';

function authLdap_debug($message)
{
	if (authLdap_get_option('Debug')) {
		error_log('[AuthLDAP] ' . $message, 0);
	}
}


function authLdap_addmenu()
{
	if (!is_multisite()) {
		add_options_page(
			'AuthLDAP',
			'AuthLDAP',
			'manage_options',
			basename(__FILE__),
			'authLdap_options_panel'
		);
	} else {
		add_submenu_page(
			'settings.php',
			'AuthLDAP',
			'AuthLDAP',
			'manage_options',
			'authldap',
			'authLdap_options_panel'
		);
	}
}

function authLdap_get_post($name, $default = '')
{
	return isset($_POST[$name]) ? $_POST[$name] : $default;
}

function authLdap_options_panel()
{
	// inclusde style sheet
	wp_enqueue_style('authLdap-style', plugin_dir_url(__FILE__) . 'authLdap.css');

	if (($_SERVER['REQUEST_METHOD'] == 'POST') && array_key_exists('ldapOptionsSave', $_POST)) {
		if (!isset($_POST['authLdapNonce'])) {
			die("Go away!");
		}
		if (!wp_verify_nonce($_POST['authLdapNonce'], 'authLdapNonce')) {
			die("Go away!");
		}

		$new_options = [
			'Enabled' => authLdap_get_post('authLDAPAuth', false),
			'CachePW' => authLdap_get_post('authLDAPCachePW', false),
			'URI' => authLdap_get_post('authLDAPURI'),
			'URISeparator' => authLdap_get_post('authLDAPURISeparator'),
			'StartTLS' => authLdap_get_post('authLDAPStartTLS', false),
			'Filter' => authLdap_get_post('authLDAPFilter'),
			'NameAttr' => authLdap_get_post('authLDAPNameAttr'),
			'SecName' => authLdap_get_post('authLDAPSecName'),
			'UidAttr' => authLdap_get_post('authLDAPUidAttr'),
			'MailAttr' => authLdap_get_post('authLDAPMailAttr'),
			'WebAttr' => authLdap_get_post('authLDAPWebAttr'),
			'Groups' => authLdap_get_post('authLDAPGroups', []),
			'GroupSeparator' => authLdap_get_post('authLDAPGroupSeparator', ','),
			'Debug' => authLdap_get_post('authLDAPDebug', false),
			'GroupBase' => authLdap_get_post('authLDAPGroupBase'),
			'GroupAttr' => authLdap_get_post('authLDAPGroupAttr'),
			'GroupFilter' => authLdap_get_post('authLDAPGroupFilter'),
			'DefaultRole' => authLdap_get_post('authLDAPDefaultRole'),
			'GroupEnable' => authLdap_get_post('authLDAPGroupEnable', false),
			'GroupOverUser' => authLdap_get_post('authLDAPGroupOverUser', false),
			'DoNotOverwriteNonLdapUsers' => authLdap_get_post('authLDAPDoNotOverwriteNonLdapUsers', false),
			'UserRead' => authLdap_get_post('authLDAPUseUserAccount', false),
		];
		if (authLdap_set_options($new_options)) {
			echo "<div class='updated'><p>Saved Options!</p></div>";
		} else {
			echo "<div class='error'><p>Could not save Options!</p></div>";
		}
	}

	// Do some initialization for the admin-view
	$authLDAP = authLdap_get_option('Enabled');
	$authLDAPCachePW = authLdap_get_option('CachePW');
	$authLDAPURI = authLdap_get_option('URI');
	$authLDAPURISeparator = authLdap_get_option('URISeparator');
	$authLDAPStartTLS = authLdap_get_option('StartTLS');
	$authLDAPFilter = authLdap_get_option('Filter');
	$authLDAPNameAttr = authLdap_get_option('NameAttr');
	$authLDAPSecName = authLdap_get_option('SecName');
	$authLDAPMailAttr = authLdap_get_option('MailAttr');
	$authLDAPUidAttr = authLdap_get_option('UidAttr');
	$authLDAPWebAttr = authLdap_get_option('WebAttr');
	$authLDAPGroups = authLdap_get_option('Groups');
	$authLDAPGroupSeparator = authLdap_get_option('GroupSeparator');
	$authLDAPDebug = authLdap_get_option('Debug');
	$authLDAPGroupBase = authLdap_get_option('GroupBase');
	$authLDAPGroupAttr = authLdap_get_option('GroupAttr');
	$authLDAPGroupFilter = authLdap_get_option('GroupFilter');
	$authLDAPDefaultRole = authLdap_get_option('DefaultRole');
	$authLDAPGroupEnable = authLdap_get_option('GroupEnable');
	$authLDAPGroupOverUser = authLdap_get_option('GroupOverUser');
	$authLDAPDoNotOverwriteNonLdapUsers = authLdap_get_option('DoNotOverwriteNonLdapUsers');
	$authLDAPUseUserAccount = authLdap_get_option('UserRead');

	$tChecked = ($authLDAP) ? ' checked="checked"' : '';
	$tDebugChecked = ($authLDAPDebug) ? ' checked="checked"' : '';
	$tPWChecked = ($authLDAPCachePW) ? ' checked="checked"' : '';
	$tGroupChecked = ($authLDAPGroupEnable) ? ' checked="checked"' : '';
	$tGroupOverUserChecked = ($authLDAPGroupOverUser) ? ' checked="checked"' : '';
	$tStartTLSChecked = ($authLDAPStartTLS) ? ' checked="checked"' : '';
	$tDoNotOverwriteNonLdapUsers = ($authLDAPDoNotOverwriteNonLdapUsers) ? ' checked="checked"' : '';
	$tUserRead = ($authLDAPUseUserAccount) ? ' checked="checked"' : '';

	$roles = new WP_Roles();

	$action = $_SERVER['REQUEST_URI'];
	if (!extension_loaded('ldap')) {
		echo '<div class="warning">The LDAP-Extension is not available on your '
			. 'WebServer. Therefore Everything you can alter here does not '
			. 'make any sense!</div>';
	}

	include dirname(__FILE__) . '/view/admin.phtml';
}

/**
 * get a LDAP server object
 *
 * throws exception if there is a problem connecting
 *
 * @conf boolean authLDAPDebug true, if debugging should be turned on
 * @conf string  authLDAPURI LDAP server URI
 *
 * @return Org_Heigl\AuthLdap\LdapList LDAP server object
 */
function authLdap_get_server()
{
	static $_ldapserver = null;
	if (is_null($_ldapserver)) {
		$authLDAPDebug = authLdap_get_option('Debug');
		$authLDAPURI = explode(
			authLdap_get_option('URISeparator', ' '),
			authLdap_get_option('URI')
		);
		$authLDAPStartTLS = authLdap_get_option('StartTLS');

		//$authLDAPURI = 'ldap:/foo:bar@server/trallala';
		authLdap_debug('connect to LDAP server');
		require_once dirname(__FILE__) . '/src/LdapList.php';
		$_ldapserver = new LdapList();
		foreach ($authLDAPURI as $uri) {
			$_ldapserver->addLdap(new Ldap(
				new LdapFactory(),
				LdapUri::fromString($uri),
				$authLDAPStartTLS
			));
		}
	}
	return $_ldapserver;
}


/**
 * This method authenticates a user using either the LDAP or, if LDAP is not
 * available, the local database
 *
 * For this we store the hashed passwords in the WP_Database to ensure working
 * conditions even without an LDAP-Connection
 *
 * @param null|WP_User|WP_Error
 * @param string $username
 * @param string $password
 * @param boolean $already_md5
 * @return boolean true, if login was successfull or false, if it wasn't
 * @conf boolean authLDAP true, if authLDAP should be used, false if not. Defaults to false
 * @conf string authLDAPFilter LDAP filter to use to find correct user, defaults to '(uid=%s)'
 * @conf string authLDAPNameAttr LDAP attribute containing user (display) name, defaults to 'name'
 * @conf string authLDAPSecName LDAP attribute containing second name, defaults to ''
 * @conf string authLDAPMailAttr LDAP attribute containing user e-mail, defaults to 'mail'
 * @conf string authLDAPUidAttr LDAP attribute containing user id (the username we log on with), defaults to 'uid'
 * @conf string authLDAPWebAttr LDAP attribute containing user website, defaults to ''
 * @conf string authLDAPDefaultRole default role for authenticated user, defaults to ''
 * @conf boolean authLDAPGroupEnable true, if we try to map LDAP groups to Wordpress roles
 * @conf boolean authLDAPGroupOverUser true, if LDAP Groups have precedence over existing user roles
 */
function authLdap_login($user, $username, $password, $already_md5 = false)
{
	// don't do anything when authLDAP is disabled
	if (!authLdap_get_option('Enabled')) {
		authLdap_debug(
			'LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)'
		);
		return $user;
	}

	$logger = new Logger(authLdap_get_option('Debug'));
	$ldapServerList = authLdap_get_server();

	$authenticator = new Authenticate(
		UserFilter::fromString(authLdap_get_option('Filter')),
		$ldapServerList,
		$logger
	);

	$loggedInUser = $authenticator($user, $username, $password);

	if ($loggedInUser === false) {
		return false;
	}

	if ($loggedInUser instanceof LoggedInUser) {
		// The user was just logged in, so let's create a WP_User-Object from it.
		$logger->log(var_export($loggedInUser, true));
		$mapper = new LoggedInUserToWpUser(
			$ldapServerList,
			$logger,
			UserFilter::fromString(authLdap_get_option('Filter')),
			ReadLdapAsUser::fromString(authLdap_get_option('UserRead')),
			NameAttribute::fromString(authLdap_get_option('NameAttr')),
			SecondNameAttribute::fromString(authLdap_get_option('SecName')),
			MailAttribute::fromString(authLdap_get_option('MailAttr')),
			UidAttribute::fromString(authLdap_get_option('UidAttr')),
			WebAttribute::fromString(authLdap_get_option('WebAttr')),
			DoNotOverwriteNonLdapUsers::fromString(authLdap_get_option('DoNotOverwriteNonLdapUsers')),
			CachePassword::fromString(authLdap_get_option('CachePW')),
		);
		$loggedInUser = $mapper($loggedInUser);
	}

	if ($loggedInUser instanceof WP_User) {
		$logger->log(var_export(authLdap_get_option('Groups'), true));
		$authorizer = new Authorize(
			$ldapServerList,
			$logger,
			GroupOverUser::fromString(authLdap_get_option('GroupOverUser')),
			GroupEnabled::fromString(authLdap_get_option('GroupEnable')),
			DefaultRole::fromString(authLdap_get_option('DefaultRole')),
			UserFilter::fromString(authLdap_get_option('Filter')),
			GroupFilter::fromString(authLdap_get_option('GroupFilter')),
			GroupAttribute::fromString(authLdap_get_option('GroupAttr')),
			GroupBase::fromString(authLdap_get_option('GroupBase')),
			GroupSeparator::fromString(authLdap_get_option('GroupSeparator')),
			Groups::fromArray(authLdap_get_option('Groups', [])),
			UidAttribute::fromString(authLdap_get_option('UidAttr')),
		);
		$loggedInUser = $authorizer($loggedInUser);
	}

	return $loggedInUser;
}

/**
 * Get user's user id
 *
 * Returns null if username not found
 *
 * @param string $username username
 * @param string user id, null if not found
 */
function authLdap_get_uid($username)
{
	global $wpdb;

	// find out whether the user is already present in the database
	$uid = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT ID FROM {$wpdb->users} WHERE user_login = %s",
			$username
		)
	);
	if ($uid) {
		authLdap_debug("Existing user, uid = {$uid}");
		return $uid;
	} else {
		return null;
	}
}

/**
 * This function disables the password-change fields in the users preferences.
 *
 * It does not make sense to authenticate via LDAP and then allow the user to
 * change the password only in the wordpress database. And changing the password
 * LDAP-wide can not be the scope of Wordpress!
 *
 * Whether the user is an LDAP-User or not is determined using the authLDAP-Flag
 * of the users meta-informations
 *
 * @return false, if the user whose prefs are viewed is an LDAP-User, true if
 * he isn't
 * @conf boolean authLDAP
 */
function authLdap_show_password_fields($return, $user)
{
	if (!$user) {
		return true;
	}

	if (get_user_meta($user->ID, 'authLDAP')) {
		return false;
	}

	return $return;
}

/**
 * This function disables the password reset for a user.
 *
 * It does not make sense to authenticate via LDAP and then allow the user to
 * reset the password only in the wordpress database. And changing the password
 * LDAP-wide can not be the scope of Wordpress!
 *
 * Whether the user is an LDAP-User or not is determined using the authLDAP-Flag
 * of the users meta-informations
 *
 * @author chaplina (https://github.com/chaplina)
 * @conf boolean authLDAP
 * @return false, if the user is an LDAP-User, true if he isn't
 */
function authLdap_allow_password_reset($return, $userid)
{
	if (!(isset($userid))) {
		return true;
	}

	if (get_user_meta($userid, 'authLDAP')) {
		return false;
	}
	return $return;
}

/**
 * Load AuthLDAP Options
 *
 * Sets and stores defaults if options are not up to date
 */
function authLdap_load_options($reload = false)
{
	static $options = null;

	// the current version for options
	$option_version_plugin = 1;

	$optionFunction = 'get_option';
	if (is_multisite()) {
		$optionFunction = 'get_site_option';
	}
	if (is_null($options) || $reload) {
		$options = $optionFunction('authLDAPOptions', []);
	}

	// check if option version has changed (or if it's there at all)
	if (!isset($options['Version']) || ($options['Version'] != $option_version_plugin)) {
		// defaults for all options
		$options_default = [
			'Enabled' => false,
			'CachePW' => false,
			'URI' => '',
			'URISeparator' => ' ',
			'Filter' => '', // '(uid=%s)'
			'NameAttr' => '', // 'name'
			'SecName' => '',
			'UidAttr' => '', // 'uid'
			'MailAttr' => '', // 'mail'
			'WebAttr' => '',
			'Groups' => [],
			'Debug' => false,
			'GroupAttr' => '', // 'gidNumber'
			'GroupFilter' => '', // '(&(objectClass=posixGroup)(memberUid=%s))'
			'DefaultRole' => '',
			'GroupEnable' => true,
			'GroupOverUser' => true,
			'Version' => $option_version_plugin,
			'DoNotOverwriteNonLdapUsers' => false,
		];

		// check if we got a version
		if (!isset($options['Version'])) {
			// we just changed to the new option format
			// read old options, then delete them
			$old_option_new_option = [
				'authLDAP' => 'Enabled',
				'authLDAPCachePW' => 'CachePW',
				'authLDAPURI' => 'URI',
				'authLDAPFilter' => 'Filter',
				'authLDAPNameAttr' => 'NameAttr',
				'authLDAPSecName' => 'SecName',
				'authLDAPUidAttr' => 'UidAttr',
				'authLDAPMailAttr' => 'MailAttr',
				'authLDAPWebAttr' => 'WebAttr',
				'authLDAPGroups' => 'Groups',
				'authLDAPDebug' => 'Debug',
				'authLDAPGroupAttr' => 'GroupAttr',
				'authLDAPGroupFilter' => 'GroupFilter',
				'authLDAPDefaultRole' => 'DefaultRole',
				'authLDAPGroupEnable' => 'GroupEnable',
				'authLDAPGroupOverUser' => 'GroupOverUser',
			];
			foreach ($old_option_new_option as $old_option => $new_option) {
				$value = get_option($old_option, null);
				if (!is_null($value)) {
					$options[$new_option] = $value;
				}
				delete_option($old_option);
			}
			delete_option('authLDAPCookieMarker');
			delete_option('authLDAPCookierMarker');
		}

		// set default for all options that are missing
		foreach ($options_default as $key => $default) {
			if (!isset($options[$key])) {
				$options[$key] = $default;
			}
		}

		// set new version and save
		$options['Version'] = $option_version_plugin;
		update_option('authLDAPOptions', $options);
	}
	return $options;
}

/**
 * Get an individual option
 */
function authLdap_get_option($optionname, $default = null)
{
	$options = authLdap_load_options();
	if (isset($options[$optionname]) && $options[$optionname]) {
		return $options[$optionname];
	}

	if (null !== $default) {
		return $default;
	}

	//authLdap_debug('option name invalid: ' . $optionname);
	return '';
}

/**
 * Set new options
 */
function authLdap_set_options($new_options = [])
{
	// initialize the options with what we currently have
	$options = authLdap_load_options();

	// set the new options supplied
	foreach ($new_options as $key => $value) {
		$options[$key] = $value;
	}

	// store options
	$optionFunction = 'update_option';
	if (is_multisite()) {
		$optionFunction = 'update_site_option';
	}
	if ($optionFunction('authLDAPOptions', $options)) {
		// reload the option cache
		authLdap_load_options(true);

		return true;
	}

	// could not set options
	return false;
}

/**
 * Do not send an email after changing the password or the email of the user!
 *
 * @param boolean $result The initial resturn value
 * @param array $user The old userdata
 * @param array $newUserData The changed userdata
 *
 * @return bool
 */
function authLdap_send_change_email($result, $user, $newUserData)
{
	if (get_user_meta($user['ID'], 'authLDAP')) {
		return false;
	}

	return $result;
}

$hook = is_multisite() ? 'network_' : '';
add_action($hook . 'admin_menu', 'authLdap_addmenu');
add_filter('show_password_fields', 'authLdap_show_password_fields', 10, 2);
add_filter('allow_password_reset', 'authLdap_allow_password_reset', 10, 2);
add_filter('authenticate', 'authLdap_login', 10, 3);
/** This only works from WP 4.3.0 on */
add_filter('send_password_change_email', 'authLdap_send_change_email', 10, 3);
add_filter('send_email_change_email', 'authLdap_send_change_email', 10, 3);
$handler = new UserRoleHandler();
add_action('authldap_user_roles', [$handler, 'addRolesToUser'], 10, 2);
