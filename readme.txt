=== authLdap ===
Contributors: heiglandreas
Tags: ldap, auth
Requires at least: 2.5.0
Tested up to: 4.3.1
Stable tag: trunk

Use your existing LDAP flexible as authentication backend for WordPress

== Description ==

Use your existing LDAP as authentication-backend for your wordpress!

So what are the differences to other Wordpress-LDAP-Authentication-Plugins?

* Flexible: You are totaly free in which LDAP-backend to use. Due to the extensive configuration you can
freely decide how to do the authentication of your users. It simply depends on your
filters
* Independent: As soon as a user logs in, it is added/updated to the Wordpress' user-database
to allow wordpress to always use the correct data. You only have to administer your users once.
* Failsafe: Due to the users being created in Wordpress' User-database they can
also log in when the LDAP-backend currently is gone.
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
