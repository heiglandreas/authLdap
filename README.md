# authLDAP

[![Join the chat at https://gitter.im/heiglandreas/authLdap](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/heiglandreas/authLdap?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Use your existing LDAP as authentication-backend for your wordpress!

[![Build Status](https://travis-ci.org/heiglandreas/authLdap.svg?branch=master)](https://travis-ci.org/heiglandreas/authLdap)
[![WordPress Stats](https://img.shields.io/wordpress/plugin/dt/authldap.svg)](https://wordpress.org/plugins/authldap/stats/)
[![WordPress Version](https://img.shields.io/wordpress/plugin/v/authldap.svg)](https://wordpress.org/plugins/authldap/)
[![WordPress testet](https://img.shields.io/wordpress/v/authldap.svg)](https://wordpress.org/plugins/authldap/)
[![Code Climate](https://codeclimate.com/github/heiglandreas/authLdap/badges/gpa.svg)](https://codeclimate.com/github/heiglandreas/authLdap)
[![Test Coverage](https://codeclimate.com/github/heiglandreas/authLdap/badges/coverage.svg)](https://codeclimate.com/github/heiglandreas/authLdap)

So what are the differences to other Wordpress-LDAP-Authentication-Plugins?

* **Flexible**: You are totaly free in which LDAP-backend to use. Due to the extensive configuration you can
freely decide how to do the authentication of your users. It simply depends on your
filters
* **Independent**: As soon as a user logs in, it is added/updated to the Wordpress' user-database
to allow wordpress to always use the correct data. You only have to administer your users once.
* **Failsafe**: Due to the users being created in Wordpress' User-database they can
also log in when the LDAP-backend currently is gone.
* **Role-Aware**: You can map Wordpress' roles to values of an existing LDAP-attribute.

## How does the plugin work?

Well, as a matter of fact it is rather simple. The plugin verifies, that the user
seeking authentification can bind to the LDAP using the provided password.

If that is so, the user is either created or updated in the wordpress-user-database.
This update includes the provided password (so the wordpress can authenticate users
even without the LDAP), the users name according to the authLDAP-preferences and
the status of the user depending on the groups-settings of the authLDAP-preferences

Writing this plugin would not have been as easy as it has been, without the
wonderfull plugin of Alistair Young from http://www.weblogs.uhi.ac.uk/sm00ay/?p=45

## Configuration

### Usage Settings

* **Enable Authentication via LDAP** Whether you want to enable authLdap for login or not
* **debug authLdap** When you have problems with authentication via LDAP you can enable a debugging mode here.
* **Save entered Password** Decide whether passwords will be cached in your wordpress-installation. **Attention:** Without the cache your users will not be able to log into your site when your LDAP is down!

### Server Settings

* **LDAP Uri** This is the URI where your ldap-backend can be reached. More information are actually on the Configuration page
* **Filter** This is the real McCoy! The filter you define here specifies how a user will be found. Before applying the filter a %s will be replaced with the given username. This means, when a user logs in using ‘foobar’ as username the following happens:

    * **uid=%1$s** check for any LDAP-Entry that has an attribute ‘uid’ with value ‘foobar’
    * **(&(objectclass=posixAccount)(|(uid=%1$s)(mail=%1$s)))** check for any LDAP-Entry that has an attribute ‘objectclass’ with value ‘posixAccout’ and either a UID- or a mail-attribute with value ‘foobar’

    This filter is rather powerfull if used wisely.

### Creating Users

* **Name-Attribute** Which Attribute from the LDAP contains the Full or the First name of the user trying to log in. This defaults to name
* **Second Name Attribute** If the above Name-Attribute only contains the First Name of the user you can here specify an Attribute that contains the second name. This field is empty by default
* **User-ID Attribute** This field will be used as login-name for wordpress. Please give the Attribute, that is used to identify the user. This should be the same as you used in the above Filter-Option. This field defaults to uid
* **Mail Attribute** Which Attribute holds the eMail-Address of the user? If more than one eMail-Address are stored in the LDAP, only the first given is used. This field defaults to mail
* **Web-Attribute** If your users have a personal page (URI) stored in the LDAP, it can be provided here. This field is empty by default

### User-Groups for Roles

* **Group-Attribute** This is the attribute that defines the Group-ID that can be matched against the Groups defined further down This field defaults to gidNumber.
* **Group-Filter** Here you can add the filter for selecting groups for the currentlly logged in user The Filter should contain the string %s which will be replaced by the login-name of the currently logged in


## FAQ

<dl>
    <dt>Can I change a users password with this plugin?</dt>
    <dd>Short Answer: <strong>No</strong>!<br>Long Answer: As the users credentials are not
    only used for a wordpress-site when you authenticate against an LDAP but for
    many other services also chances are great that there is a centralized place
    where password-changes shall be made. We'll later allow inclusion of a link
    to such a place but currently it's not available. And as password-hashing and
    where to store it requires deeper insight into the LDAP-Server then most users
    have and admins are willing to give, password changes are out of scope of this
    plugin. If you know exactyl what you do, you might want to have a look at
    <a href="https://github.com/heiglandreas/authLdap/issues/54#issuecomment-125851029">
    issue 54</a>
    wherer a way of adding it is described!
    </dd>
    <dt>Can I add a user to the LDAP when she creates a user-account on wordpress?</dt>
    <dd>Short Answer: <strong>No</strong>!<br>Long Answer: Even though that is technically possible
    it's not in the scope of this plugin. As creating a user in an LDAP often involves
    an administrative process that has already been implemented in your departments
    administration it doesn't make sense to rebuild that - in most cases highly
    individual - process in this plugin. If you know exactly what you do, have a look at
    <a href="https://github.com/heiglandreas/authLdap/issues/65">issue 65</a>
    where <a href="https://github.com/wtfiwtz">wtfiwtz</a> shows how to implement that feature.
    </dd>
    </dl>
