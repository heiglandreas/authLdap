Feature: Log in without group assignment
	Scenario: Login without group assignment with
		Given a default configuration
		And configuration value "GroupEnable" is set to "false"
		And configuration value "DefaultRole" is set to "subscriber"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And an LDAP group "ldapgroup" exists
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup"
		And a WordPress user "wordpressuser" with name "WordPress_User" and email "wordpressuser@example.com" exists
		And a WordPress role "wordpressrole" exists
		And WordPress user "wordpressuser" has role "wordpressrole"
		And a WordPress user "ldapuser" does not exist
		When LDAP user "ldapuser" logs in with password "P@ssw0rd"
		Then the login suceeds
		And a new WordPress user "ldapuser" was created with name "LDAP User" and email "ldapuser@example.com"
		And the WordPress user "ldapuser" is member of role "subscriber"

	Scenario: Login with group assignment to multiple groups where only first wordpress group is used
		Given a default configuration
		And configuration value "GroupEnable" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And configuration value "Groups" is set to "administrator=ldapgroup" and "editor=ldapgroup"
		And configuration value "GroupAttr" is set to "cn"
		And configuration value "GroupFilter" is set to "uniquemember=%dn%"
		And configuration value "GroupOverUser" is set to "true"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And an LDAP group "ldapgroup" exists
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup"
		And a WordPress user "wordpressuser" with name "WordPress_User" and email "wordpressuser@example.com" exists
		And a WordPress role "wordpressrole" exists
		And WordPress user "wordpressuser" has role "wordpressrole"
		And a WordPress user "ldapuser" does not exist
		When LDAP user "ldapuser" logs in with password "P@ssw0rd"
		Then the login suceeds
		And a new WordPress user "ldapuser" was created with name "LDAP User" and email "ldapuser@example.com"
		And the WordPress user "ldapuser" is member of role "administrator"
		And the WordPress user "ldapuser" is not member of role "editor"
		And the WordPress user "ldapuser" is not member of role "subscriber"

	Scenario: Second Login with group assignment to multiple groups where only first wordpress group is used.
		Given a default configuration
		And configuration value "GroupEnable" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And configuration value "Groups" is set to "administrator=ldapgroup" and "editor=ldapgroup"
		And configuration value "GroupAttr" is set to "cn"
		And configuration value "GroupFilter" is set to "uniquemember=%dn%"
		And configuration value "GroupOverUser" is set to "false"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And an LDAP group "ldapgroup" exists
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup"
		And a WordPress user "wordpressuser" with name "WordPress_User" and email "wordpressuser@example.com" exists
		And a WordPress role "wordpressrole" exists
		And WordPress user "wordpressuser" has role "wordpressrole"
		And a WordPress user "ldapuser" does not exist
		And LDAP user "ldapuser" logs in with password "P@ssw0rd"
		And WordPress user "ldapuser" has role "wordpressrole"
		And the WordPress user "ldapuser" is member of role "wordpressrole"
		When LDAP user "ldapuser" logs in with password "P@ssw0rd"
		Then the login suceeds
		And the WordPress user "ldapuser" is member of role "administrator"
		And the WordPress user "ldapuser" is member of role "wordpressrole"
		And the WordPress user "ldapuser" is not member of role "editor"
		And the WordPress user "ldapuser" is not member of role "subscriber"
