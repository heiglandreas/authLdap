<?php
/*
Plugin Name: AuthLDAP
Plugin URI: https://github.com/heiglandreas/authLdap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 1.4.5
Author: Andreas Heigl <a.heigl@wdv.de>
Author URI: http://andreas.heigl.org
*/

require_once dirname( __FILE__ ) . '/ldap.php';
require_once ABSPATH . 'wp-includes/registration.php';

function authLdap_debug($message) {
    if (get_option('authLDAPDebug')) {
        error_log('[AuthLDAP] ' . $message, 0);
    }
}


function authLdap_addmenu()
{
    if (function_exists('add_options_page')) {
        add_options_page('AuthLDAP', 'AuthLDAP', 9, basename(__FILE__), 'authLdap_options_panel');
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

    if ($_POST['ldapOptionsSave']) {
        update_option('authLDAP',              authLdap_get_post('authLDAPAuth', false));
        update_option('authLDAPCachePW',       authLdap_get_post('authLDAPCachePW', false));
        update_option('authLDAPURI',           authLdap_get_post('authLDAPURI'));
        update_option('authLDAPFilter',        authLdap_get_post('authLDAPFilter'));
        update_option('authLDAPNameAttr',      authLdap_get_post('authLDAPNameAttr'));
        update_option('authLDAPSecName',       authLdap_get_post('authLDAPSecName'));
        update_option('authLDAPUidAttr',       authLdap_get_post('authLDAPUidAttr'));
        update_option('authLDAPMailAttr',      authLdap_get_post('authLDAPMailAttr'));
        update_option('authLDAPWebAttr',       authLdap_get_post('authLDAPWebAttr'));
        update_option('authLDAPGroups',        authLdap_get_post('authLDAPGroups', array()));
        update_option('authLDAPDebug',         authLdap_get_post('authLDAPDebug', false));
        update_option('authLDAPGroupAttr',     authLdap_get_post('authLDAPGroupAttr'));
        update_option('authLDAPGroupFilter',   authLdap_get_post('authLDAPGroupFilter'));
        update_option('authLDAPDefaultRole',   authLdap_get_post('authLDAPDefaultRole'));
        update_option('authLDAPGroupEnable',   authLdap_get_post('authLDAPGroupEnable', false));
        update_option('authLDAPGroupOverUser', authLdap_get_post('authLDAPGroupOverUser', false));

        echo "<div class='updated'><p>Saved Options!</p></div>";
    }

    // Do some initialization for the admin-view
    $authLDAP              = get_option('authLDAP');
    $authLDAPCachePW       = get_option('authLDAPCachePW');
    $authLDAPCookieMarker  = get_option('authLDAPCookieMarker');
    $authLDAPURI           = get_option('authLDAPURI');
    $authLDAPFilter        = get_option('authLDAPFilter');
    $authLDAPNameAttr      = get_option('authLDAPNameAttr');
    $authLDAPSecName       = get_option('authLDAPSecName');
    $authLDAPMailAttr      = get_option('authLDAPMailAttr');
    $authLDAPUidAttr       = get_option('authLDAPUidAttr');
    $authLDAPWebAttr       = get_option('authLDAPWebAttr');
    $authLDAPGroups        = get_option('authLDAPGroups');
    $authLDAPDebug         = get_option('authLDAPDebug');
    $authLDAPGroupAttr     = get_option('authLDAPGroupAttr');
    $authLDAPGroupFilter   = get_option('authLDAPGroupFilter');
    $authLDAPDefaultRole   = get_option('authLDAPDefaultRole');
    $authLDAPGroupEnable   = get_option('authLDAPGroupEnable', true);
    $authLDAPGroupOverUser = get_option('authLDAPGroupOverUser', true);

    if ($authLDAP) {
        $tChecked = ' checked="checked"';
    }
    if ($authLDAPDebug) {
        $tDebugChecked = ' checked="checked"';
    }
    if ($authLDAPCachePW) {
        $tPWChecked = ' checked="checked"';
    }
    if ($authLDAPGroupEnable) {
        $tGroupChecked = ' checked="checked"';
    }
    if ($authLDAPGroupOverUser) {
        $tGroupOverUserChecked = ' checked="checked"';
    }

    $roles = new WP_Roles();

    $action = $_SERVER['REQUEST_URI'];
    if (! extension_loaded('ldap')) {
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
 * @return object LDAP server object
 * @conf boolean authLDAPDebug true, if debugging should be turned on
 * @conf string authLDAPURI LDAP server URI
 */
function authLdap_get_server() {
    static $_server = null;
    if (is_null($_server)) {
        $authLDAPDebug = get_option('authLDAPDebug');
        $authLDAPURI   = get_option('authLDAPURI');

        //$authLDAPURI = 'ldap:/foo:bar@server/trallala';
        authLdap_debug('connect to LDAP server');
        $_server = new LDAP($authLDAPURI, $authLDAPDebug);
    }
    return $_server;
}


/**
 * This method authenticates a user using either the LDAP or, if LDAP is not
 * available, the local database
 *
 * For this we store the hashed passwords in the WP_Database to ensure working
 * conditions even without an LDAP-Connection
 *
 * @param string $username
 * @param string $password
 * @param boolean $already_md5
 * @return boolean true, if login was successfull or false, if it wasn't
 * @conf boolean authLDAP true, if authLDAP should be used, false if not. Defaults to false
 * @conf string authLDAPCookieMarker (unused?)
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
    if (! get_option('authLDAP')) {
        authLdap_debug('LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)');
        return $user;
    }

    authLdap_debug("User '$username' logging in");

    if ($username == 'admin') {
        authLdap_debug('Doing nothing for possible local user admin');
        return $user;
    }

    global $wpdb, $error;
    try {
        $authLDAP               = get_option('authLDAP');
        $authLDAPCookieMarker   = get_option('authLDAPCookieMarker');
        $authLDAPFilter         = get_option('authLDAPFilter');
        $authLDAPNameAttr       = get_option('authLDAPNameAttr');
        $authLDAPSecName        = get_option('authLDAPSecName');
        $authLDAPMailAttr       = get_option('authLDAPMailAttr');
        $authLDAPUidAttr        = get_option('authLDAPUidAttr');
        $authLDAPWebAttr        = get_option('authLDAPWebAttr');
        $authLDAPDefaultRole    = get_option('authLDAPDefaultRole');
        $authLDAPGroupEnable    = get_option('authLDAPGroupEnable', true);
        $authLDAPGroupOverUser  = get_option('authLDAPGroupOverUser', true);

        if ($authLDAP && !$authLDAPCookieMarker) {
            update_option('authLDAPCookieMarker', 'LDAP');
            $authLDAPCookieMarker = get_option('authLDAPCookieMarker');
        }

        if (! $username) {
            authLdap_debug('Username not supplied: return false');
            return false;
        }

        if (! $password) {
            authLdap_debug('Password not supplied: return false');
            $error = __('<strong>Error</strong>: The password field is empty.');
            return false;
        }
        // First check for valid values and set appropriate defaults
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

        // If already_md5 is TRUE, then we're getting the user/password from the cookie. As we don't want to store LDAP passwords in any
        // form, we've already replaced the password with the hashed username and LDAP_COOKIE_MARKER
        if ($already_md5) {
            if ($password == md5($username).md5($ldapCookieMarker)) {
                authLdap_debug('cookie authentication');
                return true;
            }
        }

        // No cookie, so have to authenticate them via LDAP
        $result = false;
        try {
            authLdap_debug('about to do LDAP authentication');
            $result = authLdap_get_server()->Authenticate($username, $password, $authLDAPFilter);
        } catch (Exception $e) {
            authLdap_debug('LDAP authentication failed with exception: ' . $e->getMessage());
            return false;
        }

        if (true !== $result) {
            authLdap_debug('LDAP authentication failed');
            // TODO what to return? WP_User object, true, false, even an WP_Error object... all seem to fall back to normal wp user authentication
            return;
        }

        authLdap_debug('LDAP authentication successfull');
        $attributes = array_values(
            array_filter(
                array(
                    $authLDAPNameAttr,
                    $authLDAPSecName,
                    $authLDAPMailAttr,
                    $authLDAPWebAttr
                )
            )
        );

        try {
            $attribs = authLdap_get_server()->search(
                sprintf($authLDAPFilter, $username),
                $attributes
            );
            // First get all the relevant group informations so we can see if
            // whether have been changes in group association of the user
            if (! isset($attribs[0]['dn'])) {
                authLdap_debug('could not get user attributes from LDAP');
                throw new UnexpectedValueException('dn has not been returned');
            }
            $dn = $attribs[0]['dn'];
        } catch(Exception $e) {
            authLdap_debug('Exception getting LDAP user: ' . $e->getMessage());
            return false;
        }

        $uid = authLdap_get_uid($username);
        $role = '';

        // we only need this if either LDAP groups are disabled or
        // if the WordPress role of the user overrides LDAP groups
        if (!$authLDAPGroupEnable || !$authLDAPGroupOverUser) {
            $role = authLdap_user_role($uid);
        }

        // do LDAP group mapping if needed
        // (if LDAP groups override worpress user role, $role is still empty)
        if (empty($role) && $authLDAPGroupEnable) {
            $role = authLdap_groupmap($username, $dn);
            authLdap_debug('role from group mapping: ' . $role);
        }

        // if we don't have a role yet, use default role
        if (empty($role) && !empty($authLDAPDefaultRole)) {
            authLdap_debug('no role yet, set default role');
            $role = $authLDAPDefaultRole;
        }

        if (empty($role)) {
            // Sorry, but you are not in any group that is allowed access
            trigger_error('no group found');
            authLdap_debug('user is not in any group that is allowed access');
            return false;
        } else {
            $roles = new WP_Roles();
            // not sure if this is needed, but it can't hurt
            if (!$roles->is_role($role)) {
                trigger_error('no group found');
                authLdap_debug('role is invalid');
                return false;
            }
        }

        // from here on, the user has access!
        // now, lets update some user details
        $user_info = array();
        $user_info['user_login'] = $username;
        $user_info['role'] = $role;
        $user_info['user_email'] = '';

        // first name
        if (isset($attribs[0][strtolower($authLDAPNameAttr)][0])) {
            $user_info['first_name'] = $attribs[0][strtolower($authLDAPNameAttr)][0];
            $user_info['display_name'] = $user_info['first_name'];
        }

        // last name
        if (isset($attribs[0][strtolower($authLDAPSecName)][0])) {
            $user_info['last_name'] = $attribs[0][strtolower($authLDAPSecName)][0];
        }

        // mail address
        if (isset($attribs[0][strtolower($authLDAPMailAttr)][0])) {
            $user_info['user_email'] = $attribs[0][strtolower($authLDAPMailAttr)][0];
        }

        // website
        if (isset($attribs[0][strtolower($authLDAPWebAttr)][0])) {
            $user_info['user_url'] = $attribs[0][strtolower($authLDAPWebAttr)][0];
        }

        // optionally store the password into the wordpress database
        if (get_option('authLDAPCachePW')) {
            $user_info['user_pass'] = wp_hash_password($password);
        } else {
            // clear the password
            $user_info['user_pass'] = '';
        }

        // add uid if user exists
        if ($uid) {
            // found user in the database
            authLdap_debug('The LDAP user has an entry in the WP-Database');
            $user_info['ID'] = $uid;
        } else {
            // new wordpress account will be created
            authLdap_debug('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');

            // set initial mail address if not provided by ldap
            if (empty($user_info['user_email'])) {
                $user_info['user_email'] = $username . '@example.com';
            }
        }

        // if the user exists, wp_insert_user will update the existing user record
        $userid = wp_insert_user($user_info);
        if (is_wp_error($userid)) {
            authLdap_debug('Error creating user : ' . $userid->get_error_message());
            trigger_error('Error creating user: ' . $userid->get_error_message());
            return $userid;
        }

        authLdap_debug('user id = ' . $userid);

        // flag the user as an ldap user so we can hide the password fields in the user profile
        update_user_meta($userid, 'authLDAP', true);

        // return a user object upon positive authorization
        return new WP_User( $userid);
    } catch (Exception $e) {
        authLdap_debug($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
        trigger_error($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
    }
}

/**
 * Get user's user id
 *
 * Returns null if username not found
 *
 * @param string $username username
 * @param string user id, null if not found
 */
function authLdap_get_uid($username) {
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
function authLdap_user_role($uid) {
    global $wpdb;

    if (!$uid) {
        return '';
    }

    $meta_value = $wpdb->get_var("SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = 'wp_capabilities' AND user_id = {$uid}");

    if (!$meta_value) {
        return '';
    }

    $capabilities = unserialize($meta_value);
    $roles = is_array($capabilities) ? array_keys($capabilities) : array('');
    $role = $roles[0];

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
        get_option('authLDAPGroups', array())
    );
    $authLDAPGroupAttr      = get_option('authLDAPGroupAttr');
    $authLDAPGroupFilter    = get_option('authLDAPGroupFilter');
    if (! $authLDAPGroupAttr) {
        $authLDAPGroupAttr = 'gidNumber';
    }
    if (! $authLDAPGroupFilter) {
        $authLDAPGroupFilter = '(&(objectClass=posixGroup)(memberUid=%s))';
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
    } catch(Exception $e) {
        authLdap_debug('Exception getting LDAP group attributes: ' . $e->getMessage());
        return '';
    }

    $grp = array();
    for ($i = 0; $i < $groups ['count']; $i++) {
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
        $currentGroup = explode(',', $val);
        // Remove whitespaces around the group-ID
        $currentGroup = array_map('trim', $currentGroup);
        if (0 < count(array_intersect($currentGroup, $grp))) {
            $role = $key;
            break;
        }
    }

    authLdap_debug("Role from LDAP group: {$role}");
    return $role;
}


if (! function_exists('wp_setcookie')):

function wp_setcookie($username, $password, $already_md5 = false, $home = '', $siteurl = '')
{
    $ldapCookieMarker = get_option('ldapCookieMarker');
    $ldapAuth = get_option('ldapAuth');

    if (($ldapAuth) && ($username != 'admin')) {
        $password = md5($username).md5($ldapCookieMarker);
    } else {
        if (!$already_md5) {
            $password = md5( md5($password) ); // Double hash the password in the cookie.
        }
    }

    if (empty($home)) {
        $cookiepath = COOKIEPATH;
    } else {
        $cookiepath = preg_replace('|https?://[^/]+|i', '', $home . '/' );
    }

    if (empty($siteurl)) {
        $sitecookiepath = SITECOOKIEPATH;
        $cookiehash = COOKIEHASH;
    } else {
        $sitecookiepath = preg_replace('|https?://[^/]+|i', '', $siteurl . '/' );
        $cookiehash = md5($siteurl);
    }

    setcookie('wordpressuser_'. $cookiehash, $username, time() + 31536000, $cookiepath);
    setcookie('wordpresspass_'. $cookiehash, $password, time() + 31536000, $cookiepath);

    if ($cookiepath != $sitecookiepath) {
        setcookie('wordpressuser_'. $cookiehash, $username, time() + 31536000, $sitecookiepath);
        setcookie('wordpresspass_'. $cookiehash, $password, time() + 31536000, $sitecookiepath);
    }
}
endif;


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
function authLdap_show_password_fields()
{
    if (! array_key_exists('user_ID', $GLOBALS)) {
        get_currentuserinfo();
    }

    if (get_usermeta($GLOBALS['user_ID'], 'authLDAP')) {
        return false;
    }
    return true;
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

add_action('admin_menu', 'authLdap_addmenu');
add_filter('show_password_fields', 'authLdap_show_password_fields');
add_filter('authenticate', 'authLdap_login', 10, 3);
