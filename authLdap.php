<?php

/*
    Plugin Name: AuthLDAP
    Plugin URI: https://github.com/heiglandreas/authLdap
    Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
    Version: 2.0.0
    Author: Andreas Heigl <a.heigl@wdv.de>
    Author URI: http://andreas.heigl.org
*/

require_once dirname(__FILE__) . '/src/ldap.php';
require_once dirname(__FILE__) . '/src/Exception.php';
require_once dirname(__FILE__) . '/src/LdapList.php';


function authLdap_debug($message)
{
    if (authLdap_get_option('Debug')) {
        error_log('[AuthLDAP] ' . $message, 0);
    }
}


function authLdap_addmenu()
{
    if (! is_multisite()) {
        add_options_page('AuthLDAP', 'AuthLDAP', 'manage_options', basename(__FILE__), 'authLdap_options_panel');
    } else {
        add_submenu_page('settings.php', 'AuthLDAP', 'AuthLDAP', 'manage_options', 'authldap', 'authLdap_options_panel');
    }
}

function authLdap_get_post($name, $default = '')
{
    return isset($_POST[$name]) ? $_POST[$name] : $default;
}

function authLdap_options_panel()
{
    // Include style sheet.
    wp_enqueue_style('authLdap-style', plugin_dir_url(__FILE__) . 'authLdap.css');

    if (($_SERVER['REQUEST_METHOD'] == 'POST') && array_key_exists('ldapOptionsSave', $_POST)) {
        $newOptions = array(
                       'Enabled'        => authLdap_get_post('authLDAPAuth', false),
                       'CachePW'        => authLdap_get_post('authLDAPCachePW', false),
                       'URI'            => authLdap_get_post('authLDAPURI'),
                       'URISeparator'   => authLdap_get_post('authLDAPURISeparator'),
                       'StartTLS'       => authLdap_get_post('authLDAPStartTLS', false),
                       'Filter'         => authLdap_get_post('authLDAPFilter'),
                       'NameAttr'       => authLdap_get_post('authLDAPNameAttr'),
                       'SecName'        => authLdap_get_post('authLDAPSecName'),
                       'UidAttr'        => authLdap_get_post('authLDAPUidAttr'),
                       'MailAttr'       => authLdap_get_post('authLDAPMailAttr'),
                       'WebAttr'        => authLdap_get_post('authLDAPWebAttr'),
                       'Groups'         => authLdap_get_post('authLDAPGroups', array()),
                       'GroupSeparator' => authLdap_get_post('authLDAPGroupSeparator', ','),
                       'Debug'          => authLdap_get_post('authLDAPDebug', false),
                       'GroupAttr'      => authLdap_get_post('authLDAPGroupAttr'),
                       'GroupFilter'    => authLdap_get_post('authLDAPGroupFilter'),
                       'DefaultRole'    => authLdap_get_post('authLDAPDefaultRole'),
                       'GroupEnable'    => authLdap_get_post('authLDAPGroupEnable', false),
                       'GroupOverUser'  => authLdap_get_post('authLDAPGroupOverUser', false),
                      );
        if (authLdap_set_options($newOptions)) {
            echo "<div class='updated'><p>Saved Options!</p></div>";
        } else {
            echo "<div class='error'><p>Could not save Options!</p></div>";
        }
    }//end if

    // Do some initialization for the admin-view.
    $authLDAP        = authLdap_get_option('Enabled');
    $authLDAPCachePW = authLdap_get_option('CachePW');
    $authLDAPURI     = authLdap_get_option('URI');
    $authLDAPURISeparator   = authLdap_get_option('URISeparator');
    $authLDAPStartTLS       = authLdap_get_option('StartTLS');
    $authLDAPFilter         = authLdap_get_option('Filter');
    $authLDAPNameAttr       = authLdap_get_option('NameAttr');
    $authLDAPSecName        = authLdap_get_option('SecName');
    $authLDAPMailAttr       = authLdap_get_option('MailAttr');
    $authLDAPUidAttr        = authLdap_get_option('UidAttr');
    $authLDAPWebAttr        = authLdap_get_option('WebAttr');
    $authLDAPGroups         = authLdap_get_option('Groups');
    $authLDAPGroupSeparator = authLdap_get_option('GroupSeparator');
    $authLDAPDebug          = authLdap_get_option('Debug');
    $authLDAPGroupAttr      = authLdap_get_option('GroupAttr');
    $authLDAPGroupFilter    = authLdap_get_option('GroupFilter');
    $authLDAPDefaultRole    = authLdap_get_option('DefaultRole');
    $authLDAPGroupEnable    = authLdap_get_option('GroupEnable');
    $authLDAPGroupOverUser  = authLdap_get_option('GroupOverUser');

    $tChecked      = ($authLDAP)               ? ' checked="checked"' : '';
    $tDebugChecked = ($authLDAPDebug)          ? ' checked="checked"' : '';
    $tPWChecked    = ($authLDAPCachePW)        ? ' checked="checked"' : '';
    $tGroupChecked = ($authLDAPGroupEnable)    ? ' checked="checked"' : '';
    $tGroupOverUserChecked = ($authLDAPGroupOverUser)  ? ' checked="checked"' : '';
    $tStartTLSChecked      = ($authLDAPStartTLS)       ? ' checked="checked"' : '';

    $roles = new WP_Roles();

    $action = $_SERVER['REQUEST_URI'];
    if (! extension_loaded('ldap')) {
        echo '<div class="warning">The LDAP-Extension is not available on your WebServer. Therefore Everything you can alter here does not make any sense!</div>';
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
 * @return Org_Heigl\AuthLdap\LDAP LDAP server object
 */
function authLdap_get_server()
{
    static $ldapserver = null;
    if (is_null($ldapserver)) {
        $authLDAPDebug    = authLdap_get_option('Debug');
        $authLDAPURI      = explode(
            authLdap_get_option('URISeparator', ' '),
            authLdap_get_option('URI')
        );
        $authLDAPStartTLS = authLdap_get_option('StartTLS');

        // $authLDAPURI = 'ldap:/foo:bar@server/trallala';
        authLdap_debug('connect to LDAP server');
        require_once dirname(__FILE__) . '/src/LdapList.php';
        $ldapserver = new \Org_Heigl\AuthLdap\LdapList();
        foreach ($authLDAPURI as $uri) {
            $ldapserver->addLdap(new \Org_Heigl\AuthLdap\LDAP($uri, $authLDAPDebug, $authLDAPStartTLS));
        }
    }
    return $ldapserver;
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
 * @param boolean $alreadyMd5
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
function authLdap_login($user, $username, $password, $alreadyMd5 = false)
{
    // Don't do anything when authLDAP is disabled.
    if (! authLdap_get_option('Enabled')) {
        authLdap_debug('LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)');
        return $user;
    }

    // If the user has already been authenticated (only in that case we get a
    // WP_User-Object as $user) we skip LDAP-authentication and simply return
    // the existing user-object.
    if ($user instanceof WP_User) {
        authLdap_debug(
            sprintf(
                'User %s has already been authenticated - skipping LDAP-Authentication',
                $user->get('nickname')
            )
        );
        return $user;
    }

    authLdap_debug("User '$username' logging in");

    if ($username == 'admin') {
        authLdap_debug('Doing nothing for possible local user admin');
        return $user;
    }

    global $wpdb, $error;
    try {
        $authLDAP            = authLdap_get_option('Enabled');
        $authLDAPFilter      = authLdap_get_option('Filter');
        $authLDAPNameAttr    = authLdap_get_option('NameAttr');
        $authLDAPSecName     = authLdap_get_option('SecName');
        $authLDAPMailAttr    = authLdap_get_option('MailAttr');
        $authLDAPUidAttr     = authLdap_get_option('UidAttr');
        $authLDAPWebAttr     = authLdap_get_option('WebAttr');
        $authLDAPDefaultRole = authLdap_get_option('DefaultRole');
        $authLDAPGroupEnable = authLdap_get_option('GroupEnable');
        $authLDAPGroupOverUser = authLdap_get_option('GroupOverUser');

        if (! $username) {
            authLdap_debug('Username not supplied: return false');
            return false;
        }

        if (! $password) {
            authLdap_debug('Password not supplied: return false');
            $error = __('<strong>Error</strong>: The password field is empty.');
            return false;
        }
        // First check for valid values and set appropriate defaults.
        if (! $authLDAPFilter) {
            $authLDAPFilter = '(uid=%s)';
        }
        if (! $authLDAPNameAttr) {
            $authLDAPNameAttr = 'name';
        }
        if (! $authLDAPMailAttr) {
            $authLDAPMailAttr = 'mail';
        }
        if (! $authLDAPUidAttr) {
            $authLDAPUidAttr = 'uid';
        }

        // If alreadyMd5 is TRUE, then we're getting the user/password from the cookie. As we don't want to store LDAP passwords in any
        // form, we've already replaced the password with the hashed username and LDAP_COOKIE_MARKER.
        if ($alreadyMd5) {
            if ($password == md5($username).md5($ldapCookieMarker)) {
                authLdap_debug('cookie authentication');
                return true;
            }
        }

        // Remove slashes as noted on https://github.com/heiglandreas/authLdap/issues/108.
        $password = stripslashes_deep($password);

        // No cookie, so have to authenticate them via LDAP.
        $result = false;
        try {
            authLdap_debug('about to do LDAP authentication');
            $result = authLdap_get_server()->Authenticate($username, $password, $authLDAPFilter);
        } catch (Exception $e) {
            authLdap_debug('LDAP authentication failed with exception: ' . $e->getMessage());
            return false;
        }

        // Rebind with the default credentials after the user has been loged in.
        // Otherwise the credentials of the user trying to login will be used.
        // This fixes #55.
        authLdap_get_server()->bind();

        if (true !== $result) {
            authLdap_debug('LDAP authentication failed');
            // TODO what to return? WP_User object, true, false, even an WP_Error object... all seem to fall back to normal wp user authentication.
            return;
        }

        authLdap_debug('LDAP authentication successfull');
        $attributes = array_values(
            array_filter(
                array(
                 $authLDAPNameAttr,
                 $authLDAPSecName,
                 $authLDAPMailAttr,
                 $authLDAPWebAttr,
                 $authLDAPUidAttr,
                )
            )
        );

        try {
            $attribs = authLdap_get_server()->search(
                sprintf($authLDAPFilter, $username),
                $attributes
            );
            // First get all the relevant group informations so we can see if
            // whether have been changes in group association of the user.
            if (! isset($attribs[0]['dn'])) {
                authLdap_debug('could not get user attributes from LDAP');
                throw new UnexpectedValueException('dn has not been returned');
            }
            if (! isset($attribs[0][strtolower($authLDAPUidAttr)][0])) {
                authLdap_debug('could not get user attributes from LDAP');
                throw new UnexpectedValueException('The user-ID attribute has not been returned');
            }

            $dn      = $attribs[0]['dn'];
            $realuid = $attribs[0][strtolower($authLDAPUidAttr)][0];
        } catch (Exception $e) {
            authLdap_debug('Exception getting LDAP user: ' . $e->getMessage());
            return false;
        }//end try

        $uid  = authLdap_get_uid($realuid);
        $role = '';

        // We only need this if either LDAP groups are disabled or
        // if the WordPress role of the user overrides LDAP groups.
        if (!$authLDAPGroupEnable || !$authLDAPGroupOverUser) {
            $role = authLdap_user_role($uid);
        }

        // Do LDAP group mapping if needed.
        // If LDAP groups override worpress user role, $role is still empty.
        if (empty($role) && $authLDAPGroupEnable) {
            $role = authLdap_groupmap($realuid, $dn);
            authLdap_debug('role from group mapping: ' . $role);
        }

        // If we don't have a role yet, use default role.
        if (empty($role) && !empty($authLDAPDefaultRole)) {
            authLdap_debug('no role yet, set default role');
            $role = $authLDAPDefaultRole;
        }

        if (empty($role)) {
            // Sorry, but you are not in any group that is allowed access.
            trigger_error('no group found');
            authLdap_debug('user is not in any group that is allowed access');
            return false;
        } else {
            $roles = new WP_Roles();
            // Not sure if this is needed, but it can't hurt.
            if (!$roles->is_role($role)) {
                trigger_error('no group found');
                authLdap_debug('role is invalid');
                return false;
            }
        }

        // From here on, the user has access!
        // Now, lets update some user details...
        $userInfo = array();
        $userInfo['user_login'] = $realuid;
        $userInfo['role']       = $role;
        $userInfo['user_email'] = '';

        // First name...
        if (isset($attribs[0][strtolower($authLDAPNameAttr)][0])) {
            $userInfo['first_name'] = $attribs[0][strtolower($authLDAPNameAttr)][0];
        }

        // Last name...
        if (isset($attribs[0][strtolower($authLDAPSecName)][0])) {
            $userInfo['last_name'] = $attribs[0][strtolower($authLDAPSecName)][0];
        }

        // Mail address...
        if (isset($attribs[0][strtolower($authLDAPMailAttr)][0])) {
            $userInfo['user_email'] = $attribs[0][strtolower($authLDAPMailAttr)][0];
        }

        // Website...
        if (isset($attribs[0][strtolower($authLDAPWebAttr)][0])) {
            $userInfo['user_url'] = $attribs[0][strtolower($authLDAPWebAttr)][0];
        }
        // Display name, nickname, nicename.
        if (array_key_exists('first_name', $userInfo)) {
            $userInfo['display_name']  = $userInfo['first_name'];
            $userInfo['nickname']      = $userInfo['first_name'];
            $userInfo['user_nicename'] = sanitize_title_with_dashes($userInfo['first_name']);
            if (array_key_exists('last_name', $userInfo)) {
                $userInfo['display_name']  .= ' ' . $userInfo['last_name'];
                $userInfo['nickname']      .= ' ' . $userInfo['last_name'];
                $userInfo['user_nicename'] .= '_' . sanitize_title_with_dashes($userInfo['last_name']);
            }
        }
        $userInfo['user_nicename'] = substr($userInfo['user_nicename'], 0, 50);
  
        // Optionally store the password into the wordpress database.
        if (authLdap_get_option('CachePW')) {
            // Password will be hashed inside wp_update_user or wp_insert_user.
            $userInfo['user_pass'] = $password;
        } else {
            // Clear the password.
            $userInfo['user_pass'] = '';
        }

        // Add uid if user exists.
        if ($uid) {
            // Found user in the database.
            authLdap_debug('The LDAP user has an entry in the WP-Database');
            $userInfo['ID'] = $uid;
            unset($userInfo['display_name'], $userInfo['nickname']);
            $userid = wp_update_user($userInfo);
        } else {
            // New wordpress account will be created.
            authLdap_debug('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');

            $userid = wp_insert_user($userInfo);
        }

        // If the user exists, wp_insert_user will update the existing user record.
        if (is_wp_error($userid)) {
            authLdap_debug('Error creating user : ' . $userid->get_error_message());
            trigger_error('Error creating user: ' . $userid->get_error_message());
            return $userid;
        }

        authLdap_debug('user id = ' . $userid);

        // Flag the user as an ldap user so we can hide the password fields in the user profile.
        update_user_meta($userid, 'authLDAP', true);

        // Return a user object upon positive authorization.
        return new WP_User($userid);
    } catch (Exception $e) {
        authLdap_debug($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
        trigger_error($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
    }//end try
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

    // Find out whether the user is already present in the database.
    $uid = $wpdb->get_var(
        $wpdb->prepare(
            'SELECT ID FROM %s WHERE user_login = %s',
            $wpdb->users,
            $username
        )
    );
    if ($uid) {
        authLdap_debug("Existing user, uid = {$uid}");
        return $uid;
    } else {
        return  null;
    }
}

/**
 * Get the user's current role
 *
 * Returns empty string if not found.
 *
 * @param int $uid wordpress user id
 * @return string role, empty if none found
 */
function authLdap_user_role($uid)
{
    global $wpdb;

    if (!$uid) {
        return '';
    }

    $metaValue = $wpdb->get_var("SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = '{$wpdb->prefix}capabilities' AND user_id = {$uid}");

    if (!$metaValue) {
        return '';
    }

    $capabilities = unserialize($metaValue);
    $roles        = is_array($capabilities) ? array_keys($capabilities) : array('');
    $role         = $roles[0];

    authLdap_debug("Existing user's role: {$role}");
    return $role;
}

/**
 * Get LDAP groups for user and map to role
 *
 * @param string $username
 * @param string $dn
 * @return string role, empty string if no mapping found, first found role otherwise
 * @conf array authLDAPGroups, associative array, role => ldap_group
 * @conf string authLDAPGroupAttr, ldap attribute that holds name of group
 * @conf string authLDAPGroupFilter, LDAP filter to find groups. can contain %s and %dn% placeholders
 */
function authLdap_groupmap($username, $dn)
{
    $authLDAPGroups         = authLdap_sort_roles_by_capabilities(
        authLdap_get_option('Groups')
    );
    $authLDAPGroupAttr      = authLdap_get_option('GroupAttr');
    $authLDAPGroupFilter    = authLdap_get_option('GroupFilter');
    $authLDAPGroupSeparator = authLdap_get_option('GroupSeparator');
    if (! $authLDAPGroupAttr) {
        $authLDAPGroupAttr = 'gidNumber';
    }
    if (! $authLDAPGroupFilter) {
        $authLDAPGroupFilter = '(&(objectClass=posixGroup)(memberUid=%s))';
    }
    if (! $authLDAPGroupSeparator) {
        $authLDAPGroupSeparator = ',';
    }

    if (!is_array($authLDAPGroups) || count(array_filter(array_values($authLDAPGroups))) == 0) {
        authLdap_debug('No group names defined');
        return '';
    }

    try {
        // To allow searches based on the DN instead of the uid, we replace the
        // string %dn% with the users DN.
        $authLDAPGroupFilter = str_replace('%dn%', $dn, $authLDAPGroupFilter);
        authLdap_debug('Group Filter: ' . json_encode($authLDAPGroupFilter));
        $groups = authLdap_get_server()->search(sprintf($authLDAPGroupFilter, $username), array($authLDAPGroupAttr));
    } catch (Exception $e) {
        authLdap_debug('Exception getting LDAP group attributes: ' . $e->getMessage());
        return '';
    }

    $grp = array();
    for ($i = 0; $i < $groups['count']; $i++) {
        for ($k = 0; $k < $groups[$i][strtolower($authLDAPGroupAttr)]['count']; $k++) {
            $grp[] = $groups[$i][strtolower($authLDAPGroupAttr)][$k];
        }
    }

    authLdap_debug('LDAP groups: ' . json_encode($grp));

    // Check whether the user is member of one of the groups that are
    // allowed acces to the blog. If the user is not member of one of
    // The groups throw her out! ;-)
    // If the user is member of more than one group only the first one
    // will be taken into account!
    $role = '';
    foreach ($authLDAPGroups as $key => $val) {
        $currentGroup = explode($authLDAPGroupSeparator, $val);
        // Remove whitespaces around the group-ID.
        $currentGroup = array_map('trim', $currentGroup);
        if (0 < count(array_intersect($currentGroup, $grp))) {
            $role = $key;
            break;
        }
    }

    authLdap_debug("Role from LDAP group: {$role}");
    return $role;
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
    if (! $user) {
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
 * Sort the given roles by number of capabilities
 *
 * @param array $roles
 *
 * @return array
 */
function authLdap_sort_roles_by_capabilities($roles)
{
    global $wpdb;
    $myRoles = get_option($wpdb->get_blog_prefix() . 'user_roles');

    authLdap_debug(print_r($roles, true));
    uasort($myRoles, 'authLdap_sortByCapabilitycount');

    $return = array();

    foreach ($myRoles as $key => $role) {
        if (isset($roles[$key])) {
            $return[$key] = $roles[$key];
        }
    }

    authLdap_debug(print_r($return, true));
    return $return;
}

/**
 * Sort according to the number of capabilities
 *
 * @param $a
 * @param $b
 */
function authLdap_sortByCapabilitycount($a, $b)
{
    if (count($a['capabilities']) > count($b['capabilities'])) {
        return -1;
    }
    if (count($a['capabilities']) < count($b['capabilities'])) {
        return 1;
    }

    return 0;
}

/**
 * Load AuthLDAP Options
 *
 * Sets and stores defaults if options are not up to date
 */
function authLdap_load_options($reload = false)
{
    static $options = null;

    // The current version for options!
    $optionVersionPlugin = 1;

    $optionFunction = 'get_option';
    if (is_multisite()) {
        $optionFunction = 'get_site_option';
    }
    if (is_null($options) || $reload) {
        $options = $optionFunction('authLDAPOptions', array());
    }

    // Check if option version has changed (or if it's there at all).
    if (!isset($options['Version']) || ($options['Version'] != $optionVersionPlugin)) {
        // Defaults for all options.
        $optionsDefault = [
                           'Enabled'       => false,
                           'CachePW'       => false,
                           'URI'           => '',
                           'URISeparator'  => ' ',
                           'Filter'        => '',
                           'NameAttr'      => '',
                           'SecName'       => '',
                           'UidAttr'       => '',
                           'MailAttr'      => '',
                           'WebAttr'       => '',
                           'Groups'        => array(),
                           'Debug'         => false,
                           'GroupAttr'     => '',
                           'GroupFilter'   => '',
                           'DefaultRole'   => '',
                           'GroupEnable'   => true,
                           'GroupOverUser' => true,
                           'Version'       => $optionVersionPlugin,
                          ];

        // Check if we got a version.
        if (!isset($options['Version'])) {
            // We just changed to the new option format, so
            // read old options, then delete them.
            $oldOptionNewOption = array(
                                   'authLDAP'              => 'Enabled',
                                   'authLDAPCachePW'       => 'CachePW',
                                   'authLDAPURI'           => 'URI',
                                   'authLDAPFilter'        => 'Filter',
                                   'authLDAPNameAttr'      => 'NameAttr',
                                   'authLDAPSecName'       => 'SecName',
                                   'authLDAPUidAttr'       => 'UidAttr',
                                   'authLDAPMailAttr'      => 'MailAttr',
                                   'authLDAPWebAttr'       => 'WebAttr',
                                   'authLDAPGroups'        => 'Groups',
                                   'authLDAPDebug'         => 'Debug',
                                   'authLDAPGroupAttr'     => 'GroupAttr',
                                   'authLDAPGroupFilter'   => 'GroupFilter',
                                   'authLDAPDefaultRole'   => 'DefaultRole',
                                   'authLDAPGroupEnable'   => 'GroupEnable',
                                   'authLDAPGroupOverUser' => 'GroupOverUser',
                                  );
            foreach ($oldOptionNewOption as $oldOption => $newOption) {
                $value = get_option($oldOption, null);
                if (!is_null($value)) {
                    $options[$newOption] = $value;
                }
                delete_option($oldOption);
            }
            delete_option('authLDAPCookieMarker');
            delete_option('authLDAPCookierMarker');
        }//end if

        // Set default for all options that are missing.
        foreach ($optionsDefault as $key => $default) {
            if (!isset($options[$key])) {
                $options[$key] = $default;
            }
        }

        // Set new version and save.
        $options['Version'] = $optionVersionPlugin;
        update_option('authLDAPOptions', $options);
    }//end if
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

    return null;
}

/**
 * Set new options
 */
function authLdap_set_options($newOptions = array())
{
    // Initialize the options with what we currently have.
    $options = authLdap_load_options();

    // Set the new options supplied.
    foreach ($newOptions as $key => $value) {
        $options[$key] = $value;
    }

    // Store options.
    $optionFunction = 'update_option';
    if (is_multisite()) {
        $optionFunction = 'update_site_option';
    }
    if ($optionFunction('authLDAPOptions', $options)) {
        // Reload the option cache.
        authLdap_load_options(true);

        return true;
    }

    // Could not set options.
    return false;
}

/**
 * Do not send an email after changing the password or the email of the user!
 *
 * @param boolean $result      The initial resturn value
 * @param array   $user        The old userdata
 * @param array   $newUserData The changed userdata
 *
 * @return bool
 */
function authLdap_send_change_email($result, $user, $newUserData)
{
    if (get_usermeta($user['ID'], 'authLDAP')) {
        return false;
    }

    return $result;
}

$hook = is_multisite() ? 'network_' : '';
add_action($hook . 'admin_menu', 'authLdap_addmenu');
add_filter('show_password_fields', 'authLdap_show_password_fields', 10, 2);
add_filter('allow_password_reset', 'authLdap_allow_password_reset', 10, 2);
add_filter('authenticate', 'authLdap_login', 10, 3);
// This only works from WP 4.3.0 on!
add_filter('send_password_change_email', 'authLdap_send_change_email', 10, 3);
add_filter('send_email_change_email', 'authLdap_send_change_email', 10, 3);
