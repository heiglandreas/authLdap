Feature: Log in with multiple role-assignements in LDAP
	Scenario: A user logs in that has multiple LDAP-roles where each LDAP-role has an existing WordPress role that shall be assigned
		Given a default configuration
		And configuration value "GroupEnable" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And configuration value "GroupAttr" is set to "cn"
		And configuration value "GroupFilter" is set to "uniquemember=%dn%"
		And configuration value "Groups" is set to "subscriber=ldapgroup1" and "editor=ldapgroup2"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And an LDAP group "ldapgroup1" exists
		And an LDAP group "ldapgroup2" exists
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup1"
		And LDAP user "ldapuser" is member of LDAP group "ldapgroup2"
		And a WordPress user "ldapuser" does not exist
		And a WordPress filter "authLdap_allow_multiple_roles" with implementation "function():bool { return true;}"
		When LDAP user "ldapuser" logs in with password "P@ssw0rd"
		Then the login suceeds
		And the WordPress user "ldapuser" is member of role "subscriber"
		And the WordPress user "ldapuser" is member of role "editor"
