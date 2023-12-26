Feature: Log in without group assignment
	Scenario: Login without group assignement with
		Given a default configuration
		And configuration value "GroupEnable" is set to "false"
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
