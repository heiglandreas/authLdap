<?php
/*
Plugin Name: AuthLDAP
Plugin URI: http://andreas.heigl.org/cat/dev/wp/authldap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 1.0.3
Author: Andreas Heigl <a.heigl@wdv.de>
Author URI: http://andreas.heigl.org
*/

require_once ABSPATH . 'wp-content/plugins/authldap/ldap.php';
require_once ABSPATH . 'wp-includes/registration.php';

function authldap_addmenu()
{
    if(function_exists('add_options_page'))
    {
        add_options_page('AuthLDAP', 'AuthLDAP', 9, basename(__FILE__), 'authLdapOptionsPanel');
    }
}

function authldap_addcss()
{
    echo "<link rel='stylesheet' href='".get_settings('siteurl')."/wp-content/plugins/authLDAP/authLDAP.css' media='screen' type='text/css' />";
}

function authldapOptionsPanel()
{
    if($_POST['ldapOptionsSave'])
    {
        update_option('authLDAP',              $_POST['authLDAPAuth']);
        update_option('authLDAPURI',           $_POST['authLDAPURI']);
        update_option('authLDAPFilter',        $_POST['authLDAPFilter']);
        update_option('authLDAPNameAttr',      $_POST['authLDAPNameAttr']);
        update_option('authLDAPSecName',       $_POST['authLDAPSecName']);
        update_option('authLDAPUidAttr',       $_POST['authLDAPUidAttr']);
        update_option('authLDAPMailAttr',      $_POST['authLDAPMailAttr']);
        update_option('authLDAPWebAttr',       $_POST['authLDAPWebAttr']);
        update_option('authLDAPGroups',        $_POST['authLDAPGroups']);
        update_option('authLDAPDebug',         $_POST['authLDAPDebug']);
        update_option('authLDAPGroupAttr',     $_POST['authLDAPGroupAttr']);
        update_option('authLDAPGroupFilter',   $_POST['authLDAPGroupFilter']);

        echo "<div class='updated'><p>Saved Options!</p></div>";
    }

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


    if($authLDAP){
        $tChecked = ' checked="checked"';
    } else {
        $fChecked =  'checked="checked"';
    }
    if($authLDAPDebug){
        $tDebugChecked = ' checked="checked"';
    } else {
        $fDebugChecked =  'checked="checked"';
    }
    $action=$_SERVER['REQUEST_URI'];
    if ( !extension_loaded ( 'ldap' ) ) {
        echo '<div class="warning">The LDAP-Extension is not available on your '
             . 'WebServer. Therefore Everything you can alter here does not '
             . 'make any sense!</div>';
    }
    echo <<<authLdapForm
    <div class="wrap">
    <h2>authLDAP Options</h2>
    <form method="post" id="authLDAP_options" action="$action">
        <fieldset class="options">
        <legend>General Usage of authLDAP</legend>
        <div class="row">
            <span class="description">Enable Authentication via LDAP?</span>
            <span class="element">
                <input type='radio' name='authLDAPAuth' value='1'$tChecked/> Yes<br />
                <input type='radio' name='authLDAPAuth' value='0'$fChecked/> No
            </span>
        </div>
        <div class="row">
            <span class="description">Debug authLDAP?</span>
            <span class="element">
                <input type='radio' name='authLDAPDebug' value='1'$tDebugChecked/> Yes<br />
                <input type='radio' name='authLDAPDebug' value='0'$fDebugChecked/> No
            </span>
        </div>
        </fieldset>
        <fieldset class="options">
        <legend>General Server Settings</legend>
        <div class="row">
            <span class="description">LDAP URI</span>
            <span class="element">
                <input type='text' name='authLDAPURI' value='$authLDAPURI' style='width: 300px;'/>
            </span>
            <p class="authLDAPDescription">The <acronym title="Uniform Ressource Identifier">URI</acronym>
                for connecting to the LDAP-Server. This usualy takes the form
                <var>&lt;scheme&gt;://&lt;user&gt;:&lt;password&gt;@&lt;server&gt;/&lt;path&gt;</var>
                according to RFC 1738.</p><p class="authLDAPDescription">
                In this case it schould be something like
                <var>ldap://uid=adminuser,dc=example,c=com:secret@ldap.example.com/dc=basePath,dc=example,c=com</var>.</p>
            <p class="authLDAPDescription">If your LDAP accepts anonymous login, you can ommit the
                user and password-Part of the URI</p>
        </div>

        <div class="row">
            <span class="description">Filter</span>
            <span class="element">
                <input type='text' name='authLDAPFilter' value='$authLDAPFilter' style='width: 450px;'/>
            </span>
            <p class="authLDAPDescription">Please provide a valid filter that can be used for querying
                the <acronym title="Lightweight Directory Access Protocol">LDAP</acronym>
                for the correct user. For more information on this
                feature have a look at <a href="http://andreas.heigl.org/cat/dev/wp/authldap">http://andreas.heigl.org/cat/dev/wp/authldap</a></p>
            <p class="authLDAPDescription">This field <strong>should</strong>
                include the string <var>%s</var> that will be replaced with the
                username provided during log-in</p><p class="authLDAPDescription">If you
                leave this field empty it defaults to <strong>(uid=%s)</strong></p>
        </div>
        </fieldset>
        <fieldset class="options">
        <legend>Settings for creating new Users</legend>
        <div class="row">
            <span class="description">Name-Attribute</span>
            <span class="element">
                <input type='text' name='authLDAPNameAttr' value='$authLDAPNameAttr' style='width: 450px;'/><br />
            </span>
            <p class="authLDAPDescription">Which Attribute from the LDAP contains
            the Full or the First name of the user trying to log in.</p>
            <p class="authLDAPDefault">This defaults to <strong>name</strong></p>
        </div>

        <div class="row">
            <span class="description">Second Name Attribute</span>
            <span class="element">
                <input type='text' name='authLDAPSecName' value='$authLDAPSecName' />
            </span>
            <p class="authLDAPDescription">If the above Name-Attribute only
            contains the First Name of the user you can here specify an Attribute
            that contains the second name.</p>
            <p class="authLDAPDefault">This field is empty by default</p>
        </div>

        <div class="row">
            <span class="description">User-ID Attribute</span>
            <span class="element">
                <input type='text' name='authLDAPUidAttr' value='$authLDAPUidAttr' />
            </span>
            <p class="authLDAPDescription">Please give the Attribute, that is
            used to identify the user. This should be the same as you used in the
            above <em>Filter</em>-Option</p>
            <p class="authLDAPDefault">This field defaults to <strong>uid</strong></p>
        </div>

        <div class="row">
            <span class="description">Mail Attribute</span>
            <span class="element">
                <input type='text' name='authLDAPMailAttr' value='$authLDAPMailAttr' />
            </span>
            <p class="authLDAPDescription">Which Attribute holds the eMail-Address of the user?</p>
            <p class="authLDAPDescription">If more than one eMail-Address are stored in the LDAP, only the first given is used</p>
            <p class="authLDAPDefault">This field defaults to <strong>mail</strong></p>
        </div>

        <div class="row">
            <span class="description">Web-Attribute</span>
            <span class="element">
                <input type='text' name='authLDAPWebAttr' value='$authLDAPWebAttr' />
            </span>
            <p class="authLDAPDescription">If your users have a personal page (URI) stored in the LDAP,
            it can be provided here.</p>
            <p class="authLDAPDefault">This field is empty by default</p>
        </div>
        </fieldset>
        <fieldset class="options">
            <legend>User-Groups for Roles</legend>
            <div class="row">
                <span class="description">Group-Attribute</span>
                <span class="element">
                    <input type='text' name='authLDAPGroupAttr' value='$authLDAPGroupAttr' />
                </span>
                <p class="authLDAPDescription">This is the attribute that defines the Group-ID that can be matched against the Groups defined further down</p>
                <p class="authLDAPDefault">This field defaults to <strong>gidNumber</strong></p>
            </div>
            <div class="row">
                <span class="description">Group-Filter</span>
                <span class="element">
                    <input type='text' name='authLDAPGroupFilter' value='$authLDAPGroupFilter' />
                </span>
                <p class="authLDAPDescription">Here you can add the filter for selecting groups for the currentlly logged in user</p>
                <p class="authLDAPDescription">The Filter should contain the string %s which will be replaced by the login-name of the currently logged in user</p>
                <p class="authLDAPDefault">This field defaults to <strong>(&amp;(objectClass=posixGroup)(memberUid=%s))</strong></p>
            </div>
        </fieldset>
        <fieldset class="options">
            <legend>Group-Memberships</legend>
authLdapForm;
    $roles = new WP_Roles();
    print_r($roles->get_names(),true);
    foreach ($roles->get_names() as $group => $vals){
        $aGroup=$authLDAPGroups[$group];
        echo '<div class="row">'
           . '    <span class="description">' . $vals . '</span>'
           . '    <span class="element">'
           . '         <input type="text" name="authLDAPGroups['.$group.']" value="'.$aGroup.'" />'
           . '     </span>'
           . '     <p class="authLDAPDescription">What LDAP-Groups shall be matched to the '.$vals.'-Role?</p>'
           . '     <p class="authLDAPDescription">Please provide a coma-separated list of values</p>'
           . '     <p class="authLDAPDefault">This field is empty by default</p>'
           . '</div';
    }

    echo <<<authLdapForm3
        </fieldset>
        <fieldset class="buttons">
        <legend>Buttons</legend>

        <p class="submit"><input type="submit" name="ldapOptionsSave" value="Save" /></p>
        </fieldset>
    </form>
    </div>
authLdapForm3;
}

//if ( !function_exists('wp_login') ) :
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
function authLdap_login($foo,$username, $password, $already_md5 = false)
{

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


        if($authLDAP && !$authLDAPCookieMarker){
            update_option("authLDAPCookierMarker", "LDAP");
            $authLDAPCookieMarker = get_option("authLDAPCookieMarker");
        }

        if(!$username){
            return false;
        }

        if(!$password){
            $error = __('<strong>Error</strong>: The password field is empty.');
            return false;
        }
        // First get whether the user is already present in the database
        $login = $wpdb->get_row("SELECT ID, user_login, user_pass, user_email, user_nicename, display_name, user_url, user_status FROM $wpdb->users WHERE user_login = '$username'");
        // Keep the admin user local in case all LDAP servers go down
        if (($authLDAP) && ($username != "admin")) {
            // If already_md5 is TRUE, then we're getting the user/password from the cookie. As we don't want to store LDAP passwords in any
            // form, we've already replaced the password with the hashed username and LDAP_COOKIE_MARKER
            if ($already_md5) {
                if ($password == md5($username).md5($ldapCookieMarker)) {
                    return true;
                }
            }

            // No cookie, so have to authenticate them via LDAP
            //$authLDAPURI = 'ldap:/foo:bar@server/trallala';
            $result = false;
            try {
                $server = new LDAP($authLDAPURI,$authLDAPDebug);
                $result = $server->Authenticate ($username, $password, $authLDAPFilter);
            } catch ( Exception $e) {
                return false;
            }
            // The user is positively matched against the ldap
            if ( true === $result ) {
                $attributes = array ($authLDAPNameAttr, $authLDAPSecName, $authLDAPMailAttr, $authLDAPWebAttr);
                try{
                    $attribs = $server->search(sprintf($authLDAPFilter,$username),$attributes);
                    // First get all the relevant group informations so we can see if
                    // whether have been changes in group association of the user
                    $groups = $server->search(sprintf($authLDAPGroupFilter,$username), array($authLDAPGroupAttr));
                }catch(Exception $e){
                    return false;
                }
                $grp = array ();
                for ( $i = 0; $i < $groups ['count']; $i++ ){
                    for ( $k = 0; $k < $groups[$i][strtolower($authLDAPGroupAttr)]['count']; $k++){
                        $grp[] = $groups[$i][strtolower($authLDAPGroupAttr)][$k];
                    }
                }

                $userid=null;
                $mail = '';
                if(isset($attribs[0][strtolower($authLDAPMailAttr)][0])){
                    $mail=$attribs[0][strtolower($authLDAPMailAttr)][0];
                }
                if ( $login ){
                    // The user already has an entry in the WP-Database, so we have
                    // to update the pasword just in case it changed
                    $array=array('ID'=> $login->ID, 'user_pass' => $password);
                    if(''!=$mail){
                        $array['user_email'] = $mail;
                    }
                    $userid = wp_update_user($array);
                } else {
                    // There is no user in the WP_Database, so we have to create one
                    // For this we have to get the groups of the user so we can find,
                    // what role the user will get
                    if(''==$mail){
                        $mail='me@example.com';
                    }
                    $userid = wp_create_user($username, $password, $mail );
                }

                if ( $userid == null){
                    return false;
                }
                $meta = get_user_meta($userid, 'capabilities');
                if ( ! is_array ( $meta )){
                    return false;
                }
                update_user_meta($userid,'first_name', $attribs[0][strtolower($authLDAPNameAttr)][0]);
                $nicename = $attribs[0][strtolower($authLDAPNameAttr)][0];
                if ( $attribs[0][strtolower($authLDAPSecName)][0]){
                    update_user_meta($userid, 'last_name', $attribs[0][strtolower($authLDAPSecName)][0]);
                    $nicename .= ' ' . $attribs[0][strtolower($authLDAPSecName)][0];
                }
                // Set the Nice-Name for display
                wp_update_user(array ('ID' => $userid, 'display_name' => $nicename));
                // Deaktivate the WYSIWYG-Editor for better Performance of the
                // FCKEditor
                update_user_meta($userid,'rich_editing', 'false');
                update_user_meta($userid,'authLDAP',true);
                foreach ($authLDAPGroups as $key => $val){
                    // check only if there is a group entry made
                    if ( $val ){
                        foreach ( explode(',',$val) as $group){
                            if ( in_array (trim($group),$grp)){
                                // The user is member of the ldap group and should
                                // be added to the appropriate group
                                update_user_meta($userid,'capabilities',array ($key => 1));
                                return true;
                            }
                        }
                    } else
                    {
                        // FIXME remove the credentials, if present!!!!
                        update_user_meta($userid,'capabilities',array ($key => 0));
                    }
                }
                //$error = __('<strong>Error</strong>: Invalid Credentials supplied');
                //return false;
            }
            // If the user is not positively matched against the ldap, it can either
            // have been wrong credentials to the ldap or it can be a local user
            // that is only present in the WP-Database.
            // therefore we just do nothing more here, but check for a local account
        } // if (LDAP_ENABLED)
        if (!$login)
        {
            $error = __('<strong>Error</strong>: Invalid Credentials.');
            return false;
        }
        else
        {
            // If the password is already_md5, it has been double hashed.
            // Otherwise, it is plain text.
            if ( ( $already_md5
                && ( $login->user_login == $username )
                &&  (md5($login->user_pass) == $password) )
              || ( ( $login->user_login == $username )
                && ( $login->user_pass == md5($password) ) ) ) {
                return true;
            } else {
                $error = __('<strong>Error</strong>: Invalid Credentials.');
                $pwd = '';
                return false;
            }
        }
    }catch (Exception $e)
    {
        trigger_ERror ( $e->getMessage() . '. Exception thrown in line ' . $e->getLine());
    }
}
//endif;
if ( !function_exists('wp_setcookie') ) :
function wp_setcookie($username, $password, $already_md5 = false, $home = '', $siteurl = '')
{
    $ldapCookieMarker = get_option("ldapCookieMarker");
    $ldapAuth = get_option("ldapAuth");

    if(($ldapAuth) && ($username != "admin"))
    {
        $password = md5($username).md5($ldapCookieMarker);
    }
    else
    {
        if(!$already_md5)
        {
            $password = md5( md5($password) ); // Double hash the password in the cookie.
        }
    }

    if(empty($home))
    {
        $cookiepath = COOKIEPATH;
    }
    else
    {
        $cookiepath = preg_replace('|https?://[^/]+|i', '', $home . '/' );
    }

    if ( empty($siteurl) )
    {
        $sitecookiepath = SITECOOKIEPATH;
        $cookiehash = COOKIEHASH;
    }
    else
    {
        $sitecookiepath = preg_replace('|https?://[^/]+|i', '', $siteurl . '/' );
        $cookiehash = md5($siteurl);
    }

    setcookie('wordpressuser_'. $cookiehash, $username, time() + 31536000, $cookiepath);
    setcookie('wordpresspass_'. $cookiehash, $password, time() + 31536000, $cookiepath);

    if ( $cookiepath != $sitecookiepath )
    {
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
    if ( ! array_key_exists ( 'user_ID', $GLOBALS )){
        get_currentuserinfo();
    }
    if ( get_usermeta($GLOBALS['user_ID'],'authLDAP')){
        return false;
    }
    return true;
}

add_action('admin_menu', 'authldap_addmenu');
add_action('admin_head', 'authldap_addcss');
add_filter('show_password_fields', 'authLDAP_show_password_fields');
add_filter('authenticate', 'authLdap_login', 10, 3);