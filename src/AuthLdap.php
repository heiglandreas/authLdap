<?php

namespace Org_Heigl\AuthLdap;

use WP_Roles;

class AuthLdap
{
    private $ldapserver;

    private $wpdb;

    private $error;

    public function __construct($wpdb, $error)
    {
        $this->wpdb = $wpdb;
        $this->error = $error;
    }

    private function debug($message)
    {
        if ($this->getOption('Debug')) {
            error_log('[AuthLDAP] ' . $message, 0);
        }
    }


    public function addmenu()
    {
        if (! is_multisite()) {
            add_options_page('AuthLDAP', 'AuthLDAP', 'manage_options', basename(__FILE__), [$this, 'optionsPanel']);
        } else {
            add_submenu_page('settings.php', 'AuthLDAP', 'AuthLDAP', 'manage_options', 'authldap', [$this, 'optionsPanel']);
        }
    }

    private function getPost($name, $default = '')
    {
        return isset($_POST[$name]) ? $_POST[$name] : $default;
    }

    public function optionsPanel()
    {
        // inclusde style sheet
        wp_enqueue_style('authLdap-style', plugin_dir_url(__DIR__) . 'authLdap.css');

        if (($_SERVER['REQUEST_METHOD'] == 'POST') && array_key_exists('ldapOptionsSave', $_POST)) {
            $new_options = array(
                'Enabled'       => $this->getPost('authLDAPAuth', false),
                'CachePW'       => $this->getPost('authLDAPCachePW', false),
                'URI'           => $this->getPost('authLDAPURI'),
                'URISeparator'  => $this->getPost('authLDAPURISeparator'),
                'StartTLS'      => $this->getPost('authLDAPStartTLS', false),
                'Filter'        => $this->getPost('authLDAPFilter'),
                'NameAttr'      => $this->getPost('authLDAPNameAttr'),
                'SecName'       => $this->getPost('authLDAPSecName'),
                'UidAttr'       => $this->getPost('authLDAPUidAttr'),
                'MailAttr'      => $this->getPost('authLDAPMailAttr'),
                'WebAttr'       => $this->getPost('authLDAPWebAttr'),
                'Groups'        => $this->getPost('authLDAPGroups', array()),
                'GroupSeparator'=> $this->getPost('authLDAPGroupSeparator', ','),
                'Debug'         => $this->getPost('authLDAPDebug', false),
                'GroupBase'     => $this->getPost('authLDAPGroupBase'),
                'GroupAttr'     => $this->getPost('authLDAPGroupAttr'),
                'GroupFilter'   => $this->getPost('authLDAPGroupFilter'),
                'DefaultRole'   => $this->getPost('authLDAPDefaultRole'),
                'GroupEnable'   => $this->getPost('authLDAPGroupEnable', false),
                'GroupOverUser' => $this->getPost('authLDAPGroupOverUser', false),
                'DoNotOverwriteNonLdapUsers' => $this->getPost('authLDAPDoNotOverwriteNonLdapUsers', false),
            );
            if ($this->setOptions($new_options)) {
                echo "<div class='updated'><p>Saved Options!</p></div>";
            } else {
                echo "<div class='error'><p>Could not save Options!</p></div>";
            }
        }

        // Do some initialization for the admin-view
        $authLDAP              = $this->getOption('Enabled');
        $authLDAPCachePW       = $this->getOption('CachePW');
        $authLDAPURI           = $this->getOption('URI');
        $authLDAPURISeparator  = $this->getOption('URISeparator');
        $authLDAPStartTLS      = $this->getOption('StartTLS');
        $authLDAPFilter        = $this->getOption('Filter');
        $authLDAPNameAttr      = $this->getOption('NameAttr');
        $authLDAPSecName       = $this->getOption('SecName');
        $authLDAPMailAttr      = $this->getOption('MailAttr');
        $authLDAPUidAttr       = $this->getOption('UidAttr');
        $authLDAPWebAttr       = $this->getOption('WebAttr');
        $authLDAPGroups        = $this->getOption('Groups');
        $authLDAPGroupSeparator= $this->getOption('GroupSeparator');
        $authLDAPDebug         = $this->getOption('Debug');
        $authLDAPGroupBase     = $this->getOption('GroupBase');
        $authLDAPGroupAttr     = $this->getOption('GroupAttr');
        $authLDAPGroupFilter   = $this->getOption('GroupFilter');
        $authLDAPDefaultRole   = $this->getOption('DefaultRole');
        $authLDAPGroupEnable   = $this->getOption('GroupEnable');
        $authLDAPGroupOverUser = $this->getOption('GroupOverUser');
        $authLDAPDoNotOverwriteNonLdapUsers = $this->getOption('DoNotOverwriteNonLdapUsers');

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

        include __DIR__ . '/../view/admin.phtml';
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
    private function getServer()
    {
        if (null === $this->ldapserver) {
            $authLDAPDebug = $this->getOption('Debug');
            $authLDAPURI   = explode(
                $this->getOption('URISeparator', ' '),
                $this->getOption('URI')
            );
            $authLDAPStartTLS = $this->getOption('StartTLS');

            //$authLDAPURI = 'ldap:/foo:bar@server/trallala';
            $this->debug('connect to LDAP server');
            $this->ldapserver = new LdapList();
            foreach ($authLDAPURI as $uri) {
                $this->ldapserver->addLdap(new LDAP($uri, $authLDAPDebug, $authLDAPStartTLS));
            }
        }
        return $this->ldapserver;
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
    public function login($user, $username, $password, $already_md5 = false)
    {
        // don't do anything when authLDAP is disabled
        if (! $this->getOption('Enabled')) {
            authLdap_debug('LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)');
            return $user;
        }

        // If the user has already been authenticated (only in that case we get a
        // WP_User-Object as $user) we skip LDAP-authentication and simply return
        // the existing user-object
        if ($user instanceof WP_User) {
            $this->debug(sprintf(
                'User %s has already been authenticated - skipping LDAP-Authentication',
                $user->get('nickname')
            ));
            return $user;
        }

        $this->debug("User '$username' logging in");

        if ($username == 'admin') {
            $this->debug('Doing nothing for possible local user admin');
            return $user;
        }

//        global $wpdb, $error;
        try {
            $authLDAP               = $this->getOption('Enabled');
            $authLDAPFilter         = $this->getOption('Filter');
            $authLDAPNameAttr       = $this->getOption('NameAttr', '');
            $authLDAPSecName        = $this->getOption('SecName', '');
            $authLDAPMailAttr       = $this->getOption('MailAttr', '');
            $authLDAPUidAttr        = $this->getOption('UidAttr', '');
            $authLDAPWebAttr        = $this->getOption('WebAttr', '');
            $authLDAPDefaultRole    = $this->getOption('DefaultRole');
            $authLDAPGroupEnable    = $this->getOption('GroupEnable');
            $authLDAPGroupOverUser  = $this->getOption('GroupOverUser');

            if (! $username) {
                $this->debug('Username not supplied: return false');
                return false;
            }

            if (! $password) {
                $this->debug('Password not supplied: return false');
                $this->error = __('<strong>Error</strong>: The password field is empty.');
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
                    $this->debug('cookie authentication');
                    return true;
                }
            }

            // Remove slashes as noted on https://github.com/heiglandreas/authLdap/issues/108
            $password = stripslashes_deep($password);

            // No cookie, so have to authenticate them via LDAP
            $result = false;
            try {
                $this->debug('about to do LDAP authentication');
                $result = $this->getServer()->Authenticate($username, $password, $authLDAPFilter);
            } catch (\Exception $e) {
                $this->debug('LDAP authentication failed with exception: ' . $e->getMessage());
                return false;
            }

            // Rebind with the default credentials after the user has been loged in
            // Otherwise the credentials of the user trying to login will be used
            // This fixes #55
            $this->getServer()->bind();

            if (true !== $result) {
                $this->debug('LDAP authentication failed');
                // TODO what to return? WP_User object, true, false, even an WP_Error object... all seem to fall back to normal wp user authentication
                return;
            }

            $this->debug('LDAP authentication successfull');
            $attributes = array_values(
                array_filter(
                    array(
                        $authLDAPNameAttr,
                        $authLDAPSecName,
                        $authLDAPMailAttr,
                        $authLDAPWebAttr,
                        $authLDAPUidAttr
                    )
                )
            );

            try {
                $attribs = $this->getServer()->search(
                    sprintf($authLDAPFilter, $username),
                    $attributes
                );
                // First get all the relevant group informations so we can see if
                // whether have been changes in group association of the user
                if (! isset($attribs[0]['dn'])) {
                    $this->debug('could not get user attributes from LDAP');
                    throw new \UnexpectedValueException('dn has not been returned');
                }
                if (! isset($attribs[0][strtolower($authLDAPUidAttr)][0])) {
                    $this->debug('could not get user attributes from LDAP');
                    throw new \UnexpectedValueException('The user-ID attribute has not been returned');
                }

                $dn = $attribs[0]['dn'];
                $realuid = $attribs[0][strtolower($authLDAPUidAttr)][0];
            } catch (\Exception $e) {
                $this->debug('Exception getting LDAP user: ' . $e->getMessage());
                return false;
            }

            $uid = $this->getUid($realuid);

            // This fixes #172
            if (true == $this->getOption('DoNotOverwriteNonLdapUsers', false)) {
                if (! get_user_meta($uid, 'authLDAP')) {
              //      return null;
                }
            }

            $role = '';

            // we only need this if either LDAP groups are disabled or
            // if the WordPress role of the user overrides LDAP groups
            if (!$authLDAPGroupEnable || !$authLDAPGroupOverUser) {
                $role = $this->userRole($uid);
            }

            // do LDAP group mapping if needed
            // (if LDAP groups override worpress user role, $role is still empty)
            if (empty($role) && $authLDAPGroupEnable) {
                $role = $this->groupmap($realuid, $dn);
                $this->debug('role from group mapping: ' . $role);
            }

            // if we don't have a role yet, use default role
            if (empty($role) && !empty($authLDAPDefaultRole)) {
                $this->debug('no role yet, set default role');
                $role = $authLDAPDefaultRole;
            }

            if (empty($role)) {
                // Sorry, but you are not in any group that is allowed access
                $this->debug('user is not in any group that is allowed access');
                return false;
            } else {
                $roles = new \WP_Roles();
                // not sure if this is needed, but it can't hurt
                if (!$roles->is_role($role)) {
                    $this->debug('role is invalid');
                    return false;
                }
            }

            // from here on, the user has access!
            // now, lets update some user details
            $user_info = array();
            $user_info['user_login'] = $realuid;
            $user_info['role'] = $role;
            $user_info['user_email'] = '';

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
            $user_info['user_nicename'] = substr((string) $user_info['user_nicename'], 0, 50);

            // optionally store the password into the wordpress database
            if ($this->getOption('CachePW')) {
                // Password will be hashed inside wp_update_user or wp_insert_user
                $user_info['user_pass'] = $password;
            } else {
                // clear the password
                $user_info['user_pass'] = '';
            }

            // add uid if user exists
            if ($uid) {
                // found user in the database
                $this->debug('The LDAP user has an entry in the WP-Database');
                $user_info['ID'] = $uid;
                unset($user_info['display_name'], $user_info['nickname']);
                $userid = wp_update_user($user_info);
            } else {
                // new wordpress account will be created
                $this->debug('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');

                $userid = wp_insert_user($user_info);
            }

            // if the user exists, wp_insert_user will update the existing user record
            if (is_wp_error($userid)) {
                $this->debug('Error creating user : ' . $userid->get_error_message());

                return $userid;
            }

            $this->debug('user id = ' . $userid);

            // flag the user as an ldap user so we can hide the password fields in the user profile
            update_user_meta($userid, 'authLDAP', true);

            // return a user object upon positive authorization
            return new \WP_User($userid);
        } catch (\Exception $e) {
            $this->debug($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
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
    private function getUid($username)
    {
        // find out whether the user is already present in the database
        $uid = $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT ID FROM {$this->wpdb->users} WHERE user_login = %s",
                $username
            )
        );
        if ($uid) {
            $this->debug("Existing user, uid = {$uid}");
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
    private function userRole($uid)
    {
        if (!$uid) {
            return '';
        }

        $meta_value = $this->wpdb->get_var("SELECT meta_value FROM {$this->wpdb->usermeta} WHERE meta_key = '{$this->wpdb->prefix}capabilities' AND user_id = {$uid}");

        if (!$meta_value) {
            return '';
        }

        $capabilities = unserialize($meta_value);
        $roles = is_array($capabilities) ? array_keys($capabilities) : array('');
        $role = $roles[0];

        $this->debug("Existing user's role: {$role}");
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
    private function groupmap($username, $dn)
    {
        $authLDAPGroups = $this->sortRolesByCapabilities(
            $this->getOption('Groups')
        );
        $authLDAPGroupBase      = $this->getOption('GroupBase');
        $authLDAPGroupAttr      = $this->getOption('GroupAttr');
        $authLDAPGroupFilter    = $this->getOption('GroupFilter');
        $authLDAPGroupSeparator = $this->getOption('GroupSeparator');
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
            $this->debug('No group names defined');
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
            $this->debug('Group Filter: ' . json_encode($authLDAPGroupFilter));
            $this->debug('Group Base: ' . $authLDAPGroupBase);
            $groups = $this->getServer()->search(
                sprintf($authLDAPGroupFilter, ldap_escape($username, '', LDAP_ESCAPE_FILTER)),
                array($authLDAPGroupAttr),
                $authLDAPGroupBase
            );
        } catch (\Exception $e) {
            $this->debug('Exception getting LDAP group attributes: ' . $e->getMessage());
            return '';
        }

        $grp = array();
        for ($i = 0; $i < $groups ['count']; $i++) {
            for ($k = 0; $k < $groups[$i][strtolower($authLDAPGroupAttr)]['count']; $k++) {
                $grp[] = $groups[$i][strtolower($authLDAPGroupAttr)][$k];
            }
        }

        $this->debug('LDAP groups: ' . json_encode($grp));

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

        $this->debug("Role from LDAP group: {$role}");
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
    public function showPasswordFields($return, $user)
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
    public function allowPasswordReset($return, $userid)
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
    private function sortRolesByCapabilities($roles)
    {
        $myRoles = get_option($this->wpdb->get_blog_prefix() . 'user_roles');

        $this->debug(print_r($roles, true));
        uasort($myRoles, function ($a, $b) {
            if (count($a['capabilities']) > count($b['capabilities'])) {
                return -1;
            }
            if (count($a['capabilities']) < count($b['capabilities'])) {
                return 1;
            }

            return 0;
        });

        $return = array();

        foreach ($myRoles as $key => $role) {
            if (isset($roles[$key])) {
                $return[$key] = $roles[$key];
            }
        }

        $this->debug(print_r($return, true));
        return $return;
    }

    /**
     * Load AuthLDAP Options
     *
     * Sets and stores defaults if options are not up to date
     */
    private function loadOptions($reload = false)
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
    private function getOption($optionname, $default = null)
    {
        $options = $this->loadOptions();
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
    private function setOptions($new_options = array())
    {
        // initialize the options with what we currently have
        $options = $this->loadOptions();

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
            $this->loadOptions(true);

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
    public function sendChangeEmail($result, $user, $newUserData)
    {
        if (get_user_meta($user['ID'], 'authLDAP')) {
            return false;
        }

        return $result;
    }
}
