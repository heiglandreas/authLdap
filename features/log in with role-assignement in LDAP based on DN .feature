Feature: Log in with role-assignement in LDAP based on DN
	Scenario: A user logs in that has an LDAP-role based on the users DN
		Given a default configuration
		And configuration value "Filter" is set to "mail=%1$s"
		And configuration value "GroupEnable" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And configuration value "GroupAttr" is set to "cn"
		And configuration value "GroupFilter" is set to "uniquemember=%dn%"
		And configuration value "Groups" is set to "subscriber=ldapgroup1" and "editor=ldapgroup3"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And an LDAP group "ldapgroup1" exists
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup1"
		And a WordPress user "ldapuser" does not exist
		When user "ldapuser@example.com" logs in with password "P@ssw0rd"
		Then the login suceeds
		And the WordPress user "ldapuser" is member of role "subscriber"
