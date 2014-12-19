<?php
/*
Plugin Name: AuthLDAP
Plugin URI: https://github.com/heiglandreas/authLdap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 1.2.1
Author: Andreas Heigl <a.heigl@wdv.de>
Author URI: http://andreas.heigl.org
*/

require_once dirname( __FILE__ ) . '/ldap.php';
require_once ABSPATH . 'wp-includes/registration.php';

function authldap_debug($message) {
    if (get_option('authLDAPDebug')) {
        error_log('[AuthLDAP] ' . $message, 0);
    }
}


function authldap_addmenu()
{
    if (function_exists('add_options_page')) {
        add_options_page('AuthLDAP', 'AuthLDAP', 9, basename(__FILE__), 'authLdap_optionsPanel');
    }
}


function authldap_optionsPanel()
{
    // inclusde style sheet
    wp_enqueue_style('authLdap-style', plugin_dir_url(__FILE__) . 'authLdap.css');

    if ($_POST['ldapOptionsSave']) {
        update_option('authLDAP',            $_POST['authLDAPAuth']);
        update_option('authLDAPCachePW',     $_POST['authLDAPCachePW']);
        update_option('authLDAPURI',         $_POST['authLDAPURI']);
        update_option('authLDAPFilter',      $_POST['authLDAPFilter']);
        update_option('authLDAPNameAttr',    $_POST['authLDAPNameAttr']);
        update_option('authLDAPSecName',     $_POST['authLDAPSecName']);
        update_option('authLDAPUidAttr',     $_POST['authLDAPUidAttr']);
        update_option('authLDAPMailAttr',    $_POST['authLDAPMailAttr']);
        update_option('authLDAPWebAttr',     $_POST['authLDAPWebAttr']);
        update_option('authLDAPGroups',      $_POST['authLDAPGroups']);
        update_option('authLDAPDebug',       $_POST['authLDAPDebug']);
        update_option('authLDAPGroupAttr',   $_POST['authLDAPGroupAttr']);
        update_option('authLDAPGroupFilter', $_POST['authLDAPGroupFilter']);

        echo "<div class='updated'><p>Saved Options!</p></div>";
    }

    $authLDAP             = get_option("authLDAP");
    $authLDAPCachePW      = get_option("authLDAPCachePW");
    $authLDAPCookieMarker = get_option("authLDAPCookieMarker");
    $authLDAPURI          = get_option("authLDAPURI");
    $authLDAPFilter       = get_option("authLDAPFilter");
    $authLDAPNameAttr     = get_option("authLDAPNameAttr");
    $authLDAPSecName      = get_option("authLDAPSecName");
    $authLDAPMailAttr     = get_option("authLDAPMailAttr");
    $authLDAPUidAttr      = get_option("authLDAPUidAttr");
    $authLDAPWebAttr      = get_option("authLDAPWebAttr");
    $authLDAPGroups       = get_option('authLDAPGroups');
    $authLDAPDebug        = get_option('authLDAPDebug');
    $authLDAPGroupAttr    = get_option('authLDAPGroupAttr');
    $authLDAPGroupFilter  = get_option('authLDAPGroupFilter');

    if ($authLDAP) {
        $tChecked = ' checked="checked"';
    } else {
        $fChecked =  'checked="checked"';
    }
    if ($authLDAPDebug) {
        $tDebugChecked = ' checked="checked"';
    } else {
        $fDebugChecked =  'checked="checked"';
    }
    if ($authLDAPCachePW) {
        $tPWChecked = ' checked="checked"';
    } else {
        $fPWChecked =  'checked="checked"';
    }

    $action = $_SERVER['REQUEST_URI'];
    if (! extension_loaded('ldap')) {
        echo '<div class="warning">The LDAP-Extension is not available on your '
            . 'WebServer. Therefore Everything you can alter here does not '
            . 'make any sense!</div>';
    }
    echo <<<authLdapForm
    <div class="wrap">
     <h2>AuthLDAP Options</h2>
     <form method="post" id="authLDAP_options" action="$action">


      <h3 class="title">General Usage of authLDAP</h3>
      <fieldset class="options">

       <div class="row">
        <span class="description">Enable Authentication via LDAP?</span>
        <span class="element">
         <input type='radio' name='authLDAPAuth' value='1'$tChecked/> Yes<br />
         <input type='radio' name='authLDAPAuth' value='0'$fChecked/> No
        </span>
       </div>

       <div class="row">
        <span class="description">Debug AuthLDAP?</span>
        <span class="element">
         <input type='radio' name='authLDAPDebug' value='1'$tDebugChecked/> Yes<br />
         <input type='radio' name='authLDAPDebug' value='0'$fDebugChecked/> No
        </span>
       </div>

       <div class="row">
        <span class="description">Save entered passwords in the wordpress user table?</span>
        <span class="element">
         <input type='radio' name='authLDAPCachePW' value='1'$tPWChecked/> Yes<br />
         <input type='radio' name='authLDAPCachePW' value='0'$fPWChecked/> No
        </span>
       </div>


      </fieldset>


      <h3 class="title">General Server Settings</h3>
      <fieldset class="options">

       <div class="row">
        <span class="description">LDAP URI</span>
        <span class="element">
         <input type='text' name='authLDAPURI' value='$authLDAPURI' style='width: 300px;'/>
        </span>
        <p class="authLDAPDescription">
         The <abbr title="Uniform Ressource Identifier">URI</abbr>
         for connecting to the LDAP-Server. This usualy takes the form
         <var>&lt;scheme&gt;://&lt;user&gt;:&lt;password&gt;@&lt;server&gt;/&lt;path&gt;</var>
         according to RFC 1738.</p><p class="authLDAPDescription">
         In this case it schould be something like
         <var>ldap://uid=adminuser,dc=example,c=com:secret@ldap.example.com/dc=basePath,dc=example,c=com</var>.
        </p>
        <p class="authLDAPDescription">
          If your LDAP accepts anonymous login, you can ommit the user and
          password-Part of the URI
            </p>
       </div>

       <div class="row">
        <span class="description">Filter</span>
        <span class="element">
         <input type='text' name='authLDAPFilter' value='$authLDAPFilter' style='width: 450px;'/>
        </span>
        <p class="authLDAPDescription">
         Please provide a valid filter that can be used for querying the
         <abbr title="Lightweight Directory Access Protocol">LDAP</abbr>
         for the correct user. For more information on this
         feature have a look at <a href="http://andreas.heigl.org/cat/dev/wp/authldap">http://andreas.heigl.org/cat/dev/wp/authldap</a>
        </p>
        <p class="authLDAPDescription">
         This field <strong>should</strong> include the string <var>%s</var>
         that will be replaced with the username provided during log-in
        </p>
        <p class="authLDAPDescription">
         If you leave this field empty it defaults to <strong>(uid=%s)</strong>
        </p>
       </div>

      </fieldset>

      <h3 class="title">Settings for creating new Users</h3>
      <fieldset class="options">

       <div class="row">
        <span class="description">Name-Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPNameAttr' value='$authLDAPNameAttr' style='width: 450px;'/><br />
        </span>
        <p class="authLDAPDescription">
         Which Attribute from the LDAP contains the Full or the First name
         of the user trying to log in.
        </p>
        <p class="authLDAPDefault">
         This defaults to <strong>name</strong>
        </p>
       </div>

       <div class="row">
        <span class="description">Second Name Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPSecName' value='$authLDAPSecName' />
        </span>
        <p class="authLDAPDescription">
         If the above Name-Attribute only contains the First Name of the
         user you can here specify an Attribute that contains the second name.
        </p>
        <p class="authLDAPDefault">
         This field is empty by default
        </p>
       </div>

       <div class="row">
        <span class="description">User-ID Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPUidAttr' value='$authLDAPUidAttr' />
        </span>
        <p class="authLDAPDescription">
         Please give the Attribute, that is used to identify the user. This
         should be the same as you used in the above <em>Filter</em>-Option
        </p>
        <p class="authLDAPDefault">
         This field defaults to <strong>uid</strong>
        </p>
       </div>

       <div class="row">
        <span class="description">Mail Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPMailAttr' value='$authLDAPMailAttr' />
        </span>
        <p class="authLDAPDescription">
         Which Attribute holds the eMail-Address of the user?
        </p>
        <p class="authLDAPDescription">
         If more than one eMail-Address are stored in the LDAP, only the first given is used
        </p>
        <p class="authLDAPDefault">
         This field defaults to <strong>mail</strong>
        </p>
       </div>

       <div class="row">
        <span class="description">Web-Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPWebAttr' value='$authLDAPWebAttr' />
        </span>
        <p class="authLDAPDescription">
         If your users have a personal page (URI) stored in the LDAP, it can
         be provided here.
        </p>
        <p class="authLDAPDefault">
         This field is empty by default
        </p>
       </div>

      </fieldset>


      <h3 class="title">Groups for Roles</h3> 
      <fieldset class="options">

       <div class="row">
        <span class="description">Group-Attribute</span>
        <span class="element">
         <input type='text' name='authLDAPGroupAttr' value='$authLDAPGroupAttr' />
        </span>
        <p class="authLDAPDescription">
         This is the attribute that defines the Group-ID that can be matched
         against the Groups defined further down
        </p>
        <p class="authLDAPDefault">
         This field defaults to <strong>gidNumber</strong>
        </p>
       </div>

       <div class="row">
        <span class="description">Group-Filter</span>
        <span class="element">
         <input type='text' name='authLDAPGroupFilter' value='$authLDAPGroupFilter' />
        </span>
        <p class="authLDAPDescription">
         Here you can add the filter for selecting groups for ther
         currentlly logged in user
        </p>
        <p class="authLDAPDescription">
         The Filter should contain the string %s which will be replaced by
         the login-name of the currently logged in user
        </p>
        <p class="authLDAPDescription">
         Alternatively the string <code>%dn%</code> will be replaced by the
         DN of the currently logged in user. This can be helpfull if
         group-memberships are defined with DNs rather than UIDs
        </p>
        <p class="authLDAPDefault">This field defaults to
         <strong>(&amp;(objectClass=posixGroup)(memberUid=%s))</strong>
        </p>
       </div>

      </fieldset>

          <h3 class="title">Role - group mapping</h3>
      <fieldset class="options">
authLdapForm;

    $roles = new WP_Roles();
    foreach ($roles->get_names() as $group => $vals) {
        $aGroup=$authLDAPGroups[$group];
        echo "<div class='row'>"
            . '    <span class="description">' . $vals . '</span>'
            . '    <span class="element">'
            . '         <input type="text" name="authLDAPGroups['.$group.']" value="'.$aGroup.'" />'
            . '     </span>'
            . '     <p class="authLDAPDescription">What LDAP-Groups shall be matched to the '.$vals.'-Role?</p>'
            . '     <p class="authLDAPDescription">Please provide a coma-separated list of values</p>'
            . '     <p class="authLDAPDefault">This field is empty by default</p>'
            . '</div>';
    }

    echo <<<authLdapForm3
      </fieldset>
      <fieldset class="buttons">
       <p class="submit">
        <input type="submit" name="ldapOptionsSave" value="Save" />
       </p>
      </fieldset>
     </form>
    </div>
authLdapForm3;

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
 * @conf boolean authLDAPDebug true, if debug messages should be logged, false if not. Defaluts to false
 * @todo add the other configuration parameters here
 */
function authLdap_login($user, $username, $password, $already_md5 = false)
{
    // don't do anything when authLDAP is disabled
    if (! get_option("authLDAP")) {
        authldap_debug('LDAP disabled in AuthLDAP plugin options (use the first option in the AuthLDAP options to enable it)');
        return $user;
    }

    authldap_debug("User '$username' logging in");

    if ($username == 'admin') {
        authldap_debug('Doing nothing for possible local user admin');
        return $user;
    }

    global $wpdb, $error;
    try {
        $authLDAP               = get_option("authLDAP");
        $authLDAPCookieMarker   = get_option("authLDAPCookieMarker");
        $authLDAPURI            = get_option("authLDAPURI");
        $authLDAPFilter         = get_option("authLDAPFilter");
        $authLDAPNameAttr       = get_option("authLDAPNameAttr");
        $authLDAPSecName        = get_option("authLDAPSecName");
        $authLDAPMailAttr       = get_option("authLDAPMailAttr");
        $authLDAPUidAttr        = get_option("authLDAPUidAttr");
        $authLDAPWebAttr        = get_option("authLDAPWebAttr");
        $authLDAPGroups         = get_option('authLDAPGroups');
        $authLDAPDebug          = get_option('authLDAPDebug');
        $authLDAPGroupAttr      = get_option('authLDAPGroupAttr');
        $authLDAPGroupFilter    = get_option('authLDAPGroupFilter');

        if ($authLDAP && !$authLDAPCookieMarker) {
            update_option("authLDAPCookierMarker", "LDAP");
            $authLDAPCookieMarker = get_option("authLDAPCookieMarker");
        }

        if (! $username) {
            authldap_debug('Username not supplied: return false');
            return false;
        }

        if (! $password) {
            authldap_debug('Password not supplied: return false');
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
        if (! $authLDAPGroupAttr) {
            $authLDAPGroupAttr = 'gidNumber';
        }
        if (! $authLDAPGroupFilter) {
            $authLDAPGroupFilter = '(&(objectClass=posixGroup)(memberUid=%s))';
        }


        // If already_md5 is TRUE, then we're getting the user/password from the cookie. As we don't want to store LDAP passwords in any
        // form, we've already replaced the password with the hashed username and LDAP_COOKIE_MARKER
        if ($already_md5) {
            if ($password == md5($username).md5($ldapCookieMarker)) {
                authldap_debug('cookie authentication');
                return true;
            }
        }

        // No cookie, so have to authenticate them via LDAP
        //$authLDAPURI = 'ldap:/foo:bar@server/trallala';
        $result = false;
        try {
            authldap_debug('about to do LDAP authentication');
            $server = new LDAP($authLDAPURI, $authLDAPDebug);
            $result = $server->Authenticate($username, $password, $authLDAPFilter);
        } catch (Exception $e) {
            authldap_debug('LDAP authentication failed with exception: ' . $e->getMessage());
            return false;
        }

        if (true !== $result) {
            authldap_debug('LDAP authentication failed');
            // TODO what to return? WP_User object, true, false, even an WP_Error object... all seem to fall back to normal wp user authentication
            return;
        }

        authldap_debug('LDAP authentication successfull');
        $attributes = array($authLDAPNameAttr, $authLDAPSecName, $authLDAPMailAttr, $authLDAPWebAttr);
        try {
            $attribs = $server->search(sprintf($authLDAPFilter, $username), $attributes);
            // First get all the relevant group informations so we can see if
            // whether have been changes in group association of the user
            if (! isset($attribs[0]['dn'])) {
                authldap_debug('could not get user attributes from LDAP');
                throw new UnexpectedValueException('dn has not been returned');
            }

            // To allow searches based on the DN instead of the uid, we replace the
            // string %dn% with the users DN.
            $authLDAPGroupFilter = str_replace('%dn%', $attribs[0]['dn'], $authLDAPGroupFilter);
            authldap_debug('Group Filter: ' . json_encode($authLDAPGroupFilter));
            $groups = $server->search(sprintf($authLDAPGroupFilter, $username), array($authLDAPGroupAttr));
        } catch(Exception $e) {
            authldap_debug('Exception getting LDAP group attributes: ' . $e->getMessage());
            return false;
        }

        $grp = array();
        for ($i = 0; $i < $groups ['count']; $i++) {
            for ($k = 0; $k < $groups[$i][strtolower($authLDAPGroupAttr)]['count']; $k++) {
                $grp[] = $groups[$i][strtolower($authLDAPGroupAttr)][$k];
            }
        }

        authldap_debug('LDAP groups: ' . json_encode($grp));

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

        if (empty($role)) {
            // Sorry, but you are not in any group that is allowed access
            trigger_error('no group found');
            authldap_debug('user is not in any group that is allowed access');
            return false;
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

        // find out whether the user is already present in the database
        $login = $wpdb->get_row("SELECT ID, user_login, user_pass FROM $wpdb->users WHERE user_login = '$username'");

        if ($login) {
            // found user in the database
            authldap_debug('The LDAP user has an entry in the WP-Database');
            $user_info['ID'] = $login->ID;
        } else {
            // new wordpress account will be created
            authldap_debug('The LDAP user does not have an entry in the WP-Database, a new WP account will be created');

            // set initial mail address if not provided by ldap
            if (empty($user_info['user_email'])) {
                $user_info['user_email'] = $username . '@example.com';
            }
        }

        // if the user exists, wp_insert_user will update the existing user record
        $userid = wp_insert_user($user_info);

        authldap_debug('user id = ' . $userid);

        // flag the user as an ldap user so we can hide the password fields in the user profile
        update_user_meta($userid, 'authLDAP', true);

        // return a user object upon positive authorization
        return new WP_User( $userid);
    } catch (Exception $e) {
        authldap_debug($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
        trigger_error($e->getMessage() . '. Exception thrown in line ' . $e->getLine());
    }
}


if (! function_exists('wp_setcookie')):

function wp_setcookie($username, $password, $already_md5 = false, $home = '', $siteurl = '')
{
    $ldapCookieMarker = get_option("ldapCookieMarker");
    $ldapAuth = get_option("ldapAuth");

    if (($ldapAuth) && ($username != "admin")) {
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
function authLDAP_show_password_fields()
{
    if (! array_key_exists('user_ID', $GLOBALS)) {
        get_currentuserinfo();
    }

    if (get_usermeta($GLOBALS['user_ID'], 'authLDAP')) {
        return false;
    }
    return true;
}

add_action('admin_menu', 'authldap_addmenu');
add_filter('show_password_fields', 'authLDAP_show_password_fields');
add_filter('authenticate', 'authLdap_login', 10, 3);
