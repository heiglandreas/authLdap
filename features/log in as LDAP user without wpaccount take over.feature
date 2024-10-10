Feature: log in as LDAP user when WP users can not log in
	Scenario: When existing wordpress users are not allowed to be overwritten
		an LDAP user that logs in will be created and log in.
		Given a default configuration
		And configuration value "DoNotOverwriteNonLdapUsers" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And an LDAP user "ldapuser" with name "LDAP User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And a WordPress user "ldapuser" does not exist
		When user "ldapuser" logs in with password "P@ssw0rd"
		Then the login suceeds
	Scenario: When existing wordpress users are not allowed to be overwritten
	a WordPress user will still be able to log in.
		Given a default configuration
		And configuration value "DoNotOverwriteNonLdapUsers" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And a WordPress user "wordpressuser" with name "WordPress_User", email "wordpressuser@example.com" and password "P@ssw0rd" exists
		And a WordPress role "wordpressrole" exists
		And WordPress user "wordpressuser" has role "wordpressrole"
		When user "wordpressuser" logs in with password "P@ssw0rd"
		Then the login suceeds
	Scenario: When existing wordpress users are not allowed to be overwritten
	an LDAP user that logs in that has the same username as an existing WordPress
	userwill not be created and login fails
		Given a default configuration
		And configuration value "DoNotOverwriteNonLdapUsers" is set to "true"
		And configuration value "DefaultRole" is set to "subscriber"
		And an LDAP user "ldapuser" with name "LDAP_User", password "P@ssw0rd" and email "ldapuser@example.com" exists
		And a WordPress user "ldapuser" with name "WordPress_User" and email "wordpressuser1@example.com" exists
		When user "ldapuser" logs in with password "P@ssw0rd"
		Then the login fails

