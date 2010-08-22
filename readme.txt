=== authLdap ===
Contributors: heiglandreas
Tags: ldap, auth
Requires at least: 2.5.0
Tested up to: 3.0.1
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

For more Information on the configuration have a look at http://andreas.heigl.org/cat/dev/wp/authldap

== Installation ==

1. Upload the extracted folder `authLdap` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the Plugin via the 'authLdap'-Configuration-Page.

== Frequently Asked Questions ==

= Where can I find more Informations about the plugin? =

Go to http://andreas.heigl.org/cat/dev/wp/authldap

== Screenshots ==

1. This screen shot description corresponds to screenshot-1.(png|jpg|jpeg|gif). Note that the screenshot is taken from
the directory of the stable readme.txt, so in this case, `/tags/4.3/screenshot-1.png` (or jpg, jpeg, gif)
2. This is the second screen shot