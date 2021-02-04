=== authLdap ===
Contributors: heiglandreas
Tags: ldap, auth, authentication, active directory, AD, openLDAP, Open Directory
Requires at least: 2.5.0
Tested up to: 5.6.0
Requires PHP: 7.2
Stable tag: trunk
License: MIT
License URI: https://opensource.org/licenses/MIT

Use your existing LDAP flexible as authentication backend for WordPress

== Description ==

Use your existing LDAP as authentication-backend for your wordpress!

So what are the differences to other Wordpress-LDAP-Authentication-Plugins?

* Flexible: You are totaly free in which LDAP-backend to use. Due to the extensive configuration you can freely decide how to do the authentication of your users. It simply depends on your filters
* Independent: As soon as a user logs in, it is added/updated to the Wordpress' user-database to allow wordpress to always use the correct data. You only have to administer your users once.
* Failsafe: Due to the users being created in Wordpress' User-database they can also log in when the LDAP-backend currently is gone.
* Role-Aware: You can map Wordpress' roles to values of an existing LDAP-attribute.

For more Information on the configuration have a look at https://github.com/heiglandreas/authLdap

== Installation ==

1. Upload the extracted folder `authLdap` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the Plugin via the 'authLdap'-Configuration-Page.

== Frequently Asked Questions ==

= Where can I find more Informations about the plugin? =

Go to https://github.com/heiglandreas/authLdap

= Where can I report issues with the plugin? =

Please use the issuetracker at https://github.com/heiglandreas/authLdap/issues

== Changelog ==

= 2.4.9 =
* Improve group-assignement UI

= 2.4.8 =
* Make textfields in settings-page wider

= 2.4.7 =
* Replace deprecated function
* Fix undefined index
* Add filter for retrieving other params at login (authLdap_filter_attributes)
* Add do_action after successfull login (authLdap_login_successful)

= 2.4.0 =
* Allow to use environment variables for LDAP-URI configuration

= 2.3.0 =
* Allow to not overwrite existing WordPress-Users with LDAP-Users as that can be a security issue.

= 2.1.0 =
* Add search-base for groups. This might come in handy for multisite-instances

= 2.0.0 =
* This new release adds Multi-Site support. It will no longer be possible to use this plugin just in one subsite of a multisite installation!
* Adds a warning screen to the config-section when no LDAPextension could be found
* Fixes an issue with the max-length of the username

= 1.5.1 =
* Fixes an issue with escaped backslashes and quotes

= 1.5.0 =
* Allows parts of the LDAP-URI to be URLEncoded
* Drops support for PHP 5.4

= 1.4.20 =
* Allows multiple LDAP-servers to be queried (given that they use the same attributes)
* Fixes issue with URL-Encoded informations (see https://github.com/heiglandreas/authLdap/issues/108)

= 1.4.19 =
* Adds support for TLS

= 1.4.14 =
* Update to showing password-fields check (thanks to @chaplina)

= 1.4.13 =
* Removed generation of default email-address (thanks to @henryk)
* Fixes password-hashing when caching passwords (thanks to @litinoveweedle)
* Removes the possibility to reset a password for LDAP-based users (thanks to @chaplina)
* Removes the password-change-Email from 4.3 on (thanks to @litinoveweedle)
* Fixes double authentication-attempt (that resulted in failed authentication) (thanks to @litinoveweedle)

= 1.4.10 =
* Cleanup by removing deprecated code
* Fixes issues with undefined variables
* Enables internal option-versioning
* Setting users nickname initially to the realname instead of the uid
* Fixes display of password-change possibility in users profile-page
= 1.4.9 =
* Fixed an issue with changing display name on every login
* Use proper way of looking up user-roles in setups w/o DB-prefix
= 1.4.8 =
* Updated version string
= 1.4.7 =
* Use default user to retrieve group menberships and not logging in user.
* return the UID from the LDAP instead of the value given by the user
* remove unnecessary checkbox
* Adds a testsuite
* Fixes PSR2 violations

[…]

= 1.2.1 =
* Fixed an issue with group-ids
* Moved the code to GitHub (https://github.com/heiglandreas/authLdap)
= 1.1.0 =
* Changed the login-process. Now users that are not allowed to login due to
missing group-memberships are not created within your blog as was the standard
until Version 1.0.3 - Thanks to alex@tayts.com
* Changed the default mail-address that is created when no mail-address can be
retrieved from the LDAP from me@example.com to $username@example.com so that
a new user can be created even though the mail address already exists in your
blog - Also thanks to alex@tayts.com
* Added support for WordPress-Table-prefixes as the capabilities of a user
are interlany stored in a field that is named "$tablePrefix_capabilities" -
again thanks to alex@tayts.com and also to sim0n of silicium.mine.nu
