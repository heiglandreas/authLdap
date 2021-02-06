<?php
/*
Plugin Name: AuthLDAP
Plugin URI: https://github.com/heiglandreas/authLdap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 2.4.10
Author: Andreas Heigl <andreas@heigl.org>
Author URI: http://andreas.heigl.org
License: MIT
License URI: https://opensource.org/licenses/MIT
*/

// phpcs:disable PSR1.Files.SideEffects

use Org_Heigl\AuthLdap\LdapUri;

require_once dirname(__FILE__) . '/ldap.php';
require_once __DIR__ . '/src/LdapUri.php';
require_once __DIR__ . '/src/Exception/Error.php';
require_once __DIR__ . '/src/Exception/InvalidLdapUri.php';

function authLdap_debug($message)
{
    if (authLdap_get_option('Debug')) {
        error_log('[AuthLDAP] ' . $message, 0);
    }
}


function authLdap_addmenu()
{
    if (! is_multisite()) {
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
        $new_options = array(
            'Enabled'       => authLdap_get_post('authLDAPAuth', false),
            'CachePW'       => authLdap_get_post('authLDAPCachePW', false),
            'URI'           => authLdap_get_post('authLDAPURI'),
            'URISeparator'  => authLdap_get_post('authLDAPURISeparator'),
            'StartTLS'      => authLdap_get_post('authLDAPStartTLS', false),
            'Filter'        => authLdap_get_post('authLDAPFilter'),
            'NameAttr'      => authLdap_get_post('authLDAPNameAttr'),
            'SecName'       => authLdap_get_post('authLDAPSecName'),
            'UidAttr'       => authLdap_get_post('authLDAPUidAttr'),
            'MailAttr'      => authLdap_get_post('authLDAPMailAttr'),
            'WebAttr'       => authLdap_get_post('authLDAPWebAttr'),
            'Groups'        => authLdap_get_post('authLDAPGroups', array()),
            'GroupSeparator'=> authLdap_get_post('authLDAPGroupSeparator', ','),
            'Debug'         => authLdap_get_post('authLDAPDebug', false),
            'GroupBase'     => authLdap_get_post('authLDAPGroupBase'),
            'GroupAttr'     => authLdap_get_post('authLDAPGroupAttr'),
            'GroupFilter'   => authLdap_get_post('authLDAPGroupFilter'),
            'DefaultRole'   => authLdap_get_post('authLDAPDefaultRole'),
            'GroupEnable'   => authLdap_get_post('authLDAPGroupEnable', false),
            'GroupOverUser' => authLdap_get_post('authLDAPGroupOverUser', false),
            'DoNotOverwriteNonLdapUsers' => authLdap_get_post('authLDAPDoNotOverwriteNonLdapUsers', false),
        );
        if (authLdap_set_options($new_options)) {
            echo "<div class='updated'><p>Saved Options!</p></div>";
        } else {
            echo "<div class='error'><p>Could not save Options!</p></div>";
        }
    }

    // Do some initialization for the admin-view
    $authLDAP              = authLdap_get_option('Enabled');
    $authLDAPCachePW       = authLdap_get_option('CachePW');
    $authLDAPURI           = authLdap_get_option('URI');
    $authLDAPURISeparator  = authLdap_get_option('URISeparator');
    $authLDAPStartTLS      = authLdap_get_option('StartTLS');
    $authLDAPFilter        = authLdap_get_option('Filter');
    $authLDAPNameAttr      = authLdap_get_option('NameAttr');
    $authLDAPSecName       = authLdap_get_option('SecName');
    $authLDAPMailAttr      = authLdap_get_option('MailAttr');
    $authLDAPUidAttr       = authLdap_get_option('UidAttr');
    $authLDAPWebAttr       = authLdap_get_option('WebAttr');
    $authLDAPGroups        = authLdap_get_option('Groups');
    $authLDAPGroupSeparator= authLdap_get_option('GroupSeparator');
    $authLDAPDebug         = authLdap_get_option('Debug');
    $authLDAPGroupBase     = authLdap_get_option('GroupBase');
    $authLDAPGroupAttr     = authLdap_get_option('GroupAttr');
    $authLDAPGroupFilter   = authLdap_get_option('GroupFilter');
    $authLDAPDefaultRole   = authLdap_get_option('DefaultRole');
    $authLDAPGroupEnable   = authLdap_get_option('GroupEnable');
    $authLDAPGroupOverUser = authLdap_get_option('GroupOverUser');
    $authLDAPDoNotOverwriteNonLdapUsers = authLdap_get_option('DoNotOverwriteNonLdapUsers');

    $tChecked              = ($authLDAP)               ? ' checked="checked"' : '';
    $tDebugChecked         = ($authLDAPDebug)          ? ' checked="checked"' : '';
    $tPWChecked            = ($authLDAPCachePW)        ? ' checked="checked"' : '';
    $tGroupChecked         = ($authLDAPGroupEnable)    ? ' checked="checked"' : '';
    $tGroupOverUserChecked = ($authLDAPGroupOverUser)  ? ' checked="checked"' : '';
    $tStartTLSChecked      = ($authLDAPStartTLS)       ? ' checked="checked"' : '';
    $tDoNotOverwriteNonLdapUsers = ($authLDAPDoNotOverwriteNonLdapUsers)       ? ' checked="checked"' : '';

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
        $authLDAPURI   = explode(
            authLdap_get_option('URISeparator', ' '),
            authLdap_get_option('URI')
        );
        $authLDAPStartTLS = authLdap_get_option('StartTLS');

        //$authLDAPURI = 'ldap:/foo:bar@server/trallala';
        authLdap_debug('connect to LDAP server');
        require_once dirname(__FILE__) . '/src/LdapList.php';
        $_ldapserver = new \Org_Heigl\AuthLdap\LdapList();
        foreach ($authLDAPURI as $uri) {
            $_ldapserver->addLdap(new \Org_Heigl\AuthLdap\LDAP(
                LdapUri::fromString($uri),
                $authLDAPDebug,
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
    if (! authLdap_get_option('Enabled')) {
        authLdap_debug(
            'LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)'
        );
        return $user;
    }

    // If the user has already been authenticated (only in that case we get a
    // WP_User-Object as $user) we skip LDAP-authentication and simply return
    // the existing user-object
    if ($user instanceof WP_User) {
        authLdap_debug(sprintf(
            'User %s has already been authenticated - skipping LDAP-Authentication',
            $user->get('nickname')
        ));
        return $user;
    }

    authLdap_debug("User '$username' logging in");

    if ($username == 'admin') {
        authLdap_debug('Doing nothing for possible local user admin');
        return $user;
    }

    global $wpdb, $error;
    try {
        $authLDAP               = authLdap_get_option('Enabled');
        $authLDAPFilter         = authLdap_get_option('Filter');
        $authLDAPNameAttr       = authLdap_get_option('NameAttr');
        $authLDAPSecName        = authLdap_get_option('SecName');
        $authLDAPMailAttr       = authLdap_get_option('MailAttr');
        $authLDAPUidAttr        = authLdap_get_option('UidAttr');
        $authLDAPWebAttr        = authLdap_get_option('WebAttr');
        $authLDAPDefaultRole    = authLdap_get_option('DefaultRole');
        $authLDAPGroupEnable    = authLdap_get_option('GroupEnable');
        $authLDAPGroupOverUser  = authLdap_get_option('GroupOverUser');

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

        // If already_md5 is TRUE, then we're getting the user/password from the cookie. As we don't want
        // to store LDAP passwords in any
        // form, we've already replaced the password with the hashed username and LDAP_COOKIE_MARKER
        if ($already_md5) {
            if ($password == md5($username).md5($ldapCookieMarker)) {
                authLdap_debug('cookie authentication');
                return true;
            }
        }

        // Remove slashes as noted on https://github.com/heiglandreas/authLdap/issues/108
        $password = stripslashes_deep($password);

        // No cookie, so have to authenticate them via LDAP
        $result = false;
        try {
            authLdap_debug('about to do LDAP authentication');
            $result = authLdap_get_server()->Authenticate($username, $password, $authLDAPFilter);
        } catch (Exception $e) {
            authLdap_debug('LDAP authentication failed with exception: ' . $e->getMessage());
            return false;
        }

        // Rebind with the default credentials after the user has been loged in
        // Otherwise the credentials of the user trying to login will be used
        // This fixes #55
        authLdap_get_server()->bind();

        if (true !== $result) {
            authLdap_debug('LDAP authentication failed');
            // TODO what to return? WP_User object, true, false, even an WP_Error object...
            // all seem to fall back to normal wp user authentication
            return;
        }

        authLdap_debug('LDAP authentication successfull');
        $attributes = array_values(
            array_filter(
                apply_filters(
                    'authLdap_filter_attributes',
                    array(
                        $authLDAPNameAttr,
                        $authLDAPSecName,
                        $authLDAPMailAttr,
                        $authLDAPWebAttr,
                        $authLDAPUidAttr
                    )
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
            if (! isset($attribs[0][strtolower($authLDAPUidAttr)][0])) {
                authLdap_debug('could not get user attributes from LDAP');
                throw new UnexpectedValueException('The user-ID attribute has not been returned');
            }

            $dn = $attribs[0]['dn'];
            $realuid = $attribs[0][strtolower($authLDAPUidAttr)][0];
        } catch (Exception $e) {
            authLdap_debug('Exception getting LDAP user: ' . $e->getMessage());
            return false;
        }

        $uid = authLdap_get_uid($realuid);

        // This fixes #172
        if (true == authLdap_get_option('DoNotOverwriteNonLdapUsers', false)) {
            if (! get_user_meta($uid, 'authLDAP')) {
                return null;
            }
        }

        $role = '';

        // we only need this if either LDAP groups are disabled or
        // if the WordPress role of the user overrides LDAP groups
        if (!$authLDAPGroupEnable || !$authLDAPGroupOverUser) {
            $role = authLdap_user_role($uid);
        }

        // do LDAP group mapping if needed
        // (if LDAP groups override worpress user role, $role is still empty)
        if (empty($role) && $authLDAPGroupEnable) {
            $role = authLdap_groupmap($realuid, $dn);
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
        $user_info['user_login'] = $realuid;
        $user_info['role'] = $role;
        $user_info['user_email'] = '';
        $user_info['user_nicename'] = '';

        // first name
        if (isset($attribs[0][strtolower($authLDAPNameAttr)][0])) {
            $user_info['first_name'] = $attribs[0][strtolower($authLDAPNameAttr)][0];
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
        // display name, nickname, nicename
        if (array_key_exists('first_name', $user_info)) {
            $user_info['display_name'] = $user_info['first_name'];
            $user_info['nickname'] = $user_info['first_name'];
            $user_info['user_nicename'] = sanitize_title_with_dashes($user_info['first_name']);
            if (array_key_exists('last_name', $user_info)) {
                $user_info['display_name'] .= ' ' . $user_info['last_name'];
                $user_info['nickname'] .= ' ' . $user_info['last_name'];
                $user_info['user_nicename'] .= '_' . sanitize_title_with_dashes($user_info['last_name']);
            }
        }
        $user_info['user_nicename'] = substr($user_info['user_nicename'], 0, 50);

        // optionally store the password into the wordpress database
        if (authLdap_get_option('CachePW')) {
            // Password will be hashed inside wp_update_user or wp_insert_user
            $user_info['user_pass'] = $password;
        } else {
            // clear the password
            $user_info['user_pass'] = '';
        }

        // add uid if user exists
        if ($uid) {
            // found user in the database
            authLdap_debug('The LDAP user has an entry in the WP-Database');
            $user_info['ID'] = $uid;
            unset($user_info['display_name'], $user_info['nickname']);
            $userid = wp_update_user($user_info);
        } else {
            // new wordpress account will be created
            authLdap_debug('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');

            $userid = wp_insert_user($user_info);
        }

        /**
         * Add hook for custom updates
         *
         * @param int $userid User ID.
         * @param array $attribs[0] Attributes retrieved from LDAP for the user.
         */
        do_action('authLdap_login_successful', $userid, $attribs[0]);

        // if the user exists, wp_insert_user will update the existing user record
        if (is_wp_error($userid)) {
            authLdap_debug('Error creating user : ' . $userid->get_error_message());
            trigger_error('Error creating user: ' . $userid->get_error_message());
            return $userid;
        }

        authLdap_debug('user id = ' . $userid);

        // flag the user as an ldap user so we can hide the password fields in the user profile
        update_user_meta($userid, 'authLDAP', true);

        // return a user object upon positive authorization
        return new WP_User($userid);
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

    $meta_value = $wpdb->get_var(
        "SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = '{$wpdb->prefix}capabilities' AND user_id = {$uid}"
    );

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
 * @conf string authLDAPGroupBase, base dn to look up groups
 * @conf string authLDAPGroupAttr, ldap attribute that holds name of group
 * @conf string authLDAPGroupFilter, LDAP filter to find groups. can contain %s and %dn% placeholders
 */
function authLdap_groupmap($username, $dn)
{
    $authLDAPGroups         = authLdap_sort_roles_by_capabilities(
        authLdap_get_option('Groups')
    );
    $authLDAPGroupBase      = authLdap_get_option('GroupBase');
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
        $authLDAPGroupFilter = str_replace(
            '%dn%',
            ldap_escape($dn, '', LDAP_ESCAPE_FILTER),
            $authLDAPGroupFilter
        );
        authLdap_debug('Group Filter: ' . json_encode($authLDAPGroupFilter));
        authLdap_debug('Group Base: ' . $authLDAPGroupBase);
        $groups = authLdap_get_server()->search(
            sprintf($authLDAPGroupFilter, ldap_escape($username, '', LDAP_ESCAPE_FILTER)),
            array($authLDAPGroupAttr),
            $authLDAPGroupBase
        );
    } catch (Exception $e) {
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
        $currentGroup = explode($authLDAPGroupSeparator, $val);
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

    // the current version for options
    $option_version_plugin = 1;

    $optionFunction = 'get_option';
    if (is_multisite()) {
        $optionFunction = 'get_site_option';
    }
    if (is_null($options) || $reload) {
        $options = $optionFunction('authLDAPOptions', array());
    }

    // check if option version has changed (or if it's there at all)
    if (!isset($options['Version']) || ($options['Version'] != $option_version_plugin)) {
        // defaults for all options
        $options_default = array(
            'Enabled'       => false,
            'CachePW'       => false,
            'URI'           => '',
            'URISeparator'  => ' ',
            'Filter'        => '', // '(uid=%s)'
            'NameAttr'      => '', // 'name'
            'SecName'       => '',
            'UidAttr'       => '', // 'uid'
            'MailAttr'      => '', // 'mail'
            'WebAttr'       => '',
            'Groups'        => array(),
            'Debug'         => false,
            'GroupAttr'     => '', // 'gidNumber'
            'GroupFilter'   => '', // '(&(objectClass=posixGroup)(memberUid=%s))'
            'DefaultRole'   => '',
            'GroupEnable'   => true,
            'GroupOverUser' => true,
            'Version'       => $option_version_plugin,
            'DoNotOverwriteNonLdapUsers' => false,
        );

        // check if we got a version
        if (!isset($options['Version'])) {
            // we just changed to the new option format
            // read old options, then delete them
            $old_option_new_option = array(
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
    return null;
}

/**
 * Set new options
 */
function authLdap_set_options($new_options = array())
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
 * @param boolean $result      The initial resturn value
 * @param array   $user        The old userdata
 * @param array   $newUserData The changed userdata
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
