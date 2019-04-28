<?php
/*
Plugin Name: AuthLDAP
Plugin URI: https://github.com/heiglandreas/authLdap
Description: This plugin allows you to use your existing LDAP as authentication base for WordPress
Version: 2.3.1
Author: Andreas Heigl <andreas@heigl.org>
Author URI: http://andreas.heigl.org
License: MIT
License URI: https://opensource.org/licenses/MIT
*/

require_once __DIR__ . '/src/Ldap.php';
require_once __DIR__ . '/src/LdapList.php';
require_once __DIR__ . '/src/AuthLdap.php';
require_once __DIR__ . '/src/LdapException.php';

$authLdap = new \Org_Heigl\AuthLdap\AuthLdap($wpdb, $error);

$hook = is_multisite() ? 'network_' : '';
add_action($hook . 'admin_menu', [$authLdap, 'addmenu']);
add_filter('show_password_fields', [$authLdap, 'showPasswordFields'], 10, 2);
add_filter('allow_password_reset', [$authLdap, 'allowPasswordReset'], 10, 2);
add_filter('authenticate', [$authLdap, 'login'], 10, 3);
/** This only works from WP 4.3.0 on */
add_filter('send_password_change_email', [$authLdap, 'sendChangeEmail'], 10, 3);
add_filter('send_email_change_email', [$authLdap, 'sendChangeEmail'], 10, 3);
