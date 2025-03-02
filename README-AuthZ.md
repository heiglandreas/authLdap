# Authorization-Only (AuthZ) Experimental Settings

Additional settings have been added to leverage authLDAP to map roles for users that are authenticating using something other than the LDAP store.

## Settings
* **Enable LDAP Group Lookup for 'External' users?** Allows users who are logging in via alternative (non-LDAP/local account) scenarios to have role mappings assigned if their user can be looked up via LDAP.
* **Allow local accounts when External Users are enabled?** When External users are allowed, also permits local accounts to still work. Without this setting, local accounts will fail the necessary group lookups, causing them to have all roles removed during session initialization.

## User types supported
1. Standard "Local" (non-LDAP) WordPress accounts
2. LDAP accounts
3. Alternative logins (social logins, OIDC, SAML, etc) where the user has an object in WordPress
   
   Support for authenticating with these types of accounts must be done via another plugin, and is not native to authLDAP.

authLDAP has always supported a combination of the first two user types. This document assumes you want to add support for the third.

## Requirements
### LDAP Requirements
- The LDAP directory must contain an entry for the user.
- The user must be able to be searched for using the same method that LDAP users are distinguished.
  - If the user cannot be found this way, they will receive the default role (if any) that your LDAP users also receive.

### Login Requirements
- The alternative authentication method must present the username the same way that WordPress would expect it, or your other plugin(s) must otherwise be able to rationalize the information to a WordPress account.
  - Making this work is an exercise for the reader, and beyond the scope of this document.
- Your authentication chain must be configured to limit the set of valid users, or anyone with an account can log in and get the default role.

### authLDAP Requirements
- Role assignment based on group membership ("Groups for Roles") is the only intended use case for these options. Without them, this is kind of worthless.
- Default Role for LDAP users will also apply to the "External" users that log in

## Configuration Scenarios
In all of the scenarios below, we have 4 example users:
1. **localadmin** - the initial WordPress account, with Administrator access assigned in the WordPress database. This account is not present in LDAP at all.
2. **ldapadmin** - an LDAP user that is part of a group mapped to the Administrator role
3. **samluser** - a user logging in via the SAML protocol, who is also present in the LDAP database and a member of the same group as ldapadmin
4. **othersamluser** - another user logging in via the SAML protocol, who is absent from the LDAP database

Regardless of settings changes, behavior surrounding the **ldapamin** account should remain unchanged.

By enabling External accounts (via the first new Experimental setting), the **samluser** account would also receive Administrator upon login - even if the WordPress database has them desginated with another setting. That role will be updated in the database on every login.

The **othersamluser** account will receive the default role for users defined by authLDAP (or be denied access), regardless of what is defined in the WordPress database. Again, this will be updated on each login. In the case where Default Role is set to None (deny access), the database is not updated with new roles if the user already exists.

The **localadmin** account will behave similarly, **EXCEPT** when the "Allow local accounts when External Users are enabled" setting is checked. With this option turned on, the roles for the local WP account will be honored. Please be advised that if **localadmin** logs in while this setting is off, their permissions will revert to the default role (or denied access without a database update).

## Recommendations for initial configuration/testing of AuthZ-only
* Back up your WordPress database to ensure you can roll back. (No seriously - this is a completely experimental feature).
* Have multiple Administrator accounts so that you can test one without disabling all access.
* Set the Default Role to "None (deny access)" until you are clear you have a stable configuration.
  * This ensures that a different Default Role doesn't clobber your existing users.
  * Generally, this is a good practice anyway, especially if your external authentication is very open.
* Make sure you have the WordPress command line tool, wp-cli, installed and can actually run it.
