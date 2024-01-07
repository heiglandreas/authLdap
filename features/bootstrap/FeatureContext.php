<?php

declare(strict_types=1);

use Behat\Behat\Tester\Exception\PendingException;
use Behat\Behat\Context\Context;
use Behat\Gherkin\Node\PyStringNode;
use Behat\Gherkin\Node\TableNode;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Psr7\Response;
use Org_Heigl\AuthLdap\OptionFactory;
use Org_Heigl\AuthLdap\Options;
use Webmozart\Assert\Assert;

class FeatureContext implements Context
{
	private ?Response $res = null;
	/**
	 * Initializes context.
	 *
	 * Every scenario gets its own context instance.
	 * You can also pass arbitrary arguments to the
	 * context constructor through behat.yml.
	 */
	public function __construct()
	{
		exec('wp --allow-root core install --url=localhost --title=Example --admin_user=localadmin --admin_password=P@ssw0rd --admin_email=info@example.com');
		exec('wp --allow-root plugin activate authldap');
	}


	/**
	 * @Given a default configuration
	 */
	public function aDefaultConfiguration()
	{
		$options = new Options();
		$options->set(Options::URI, 'ldap://cn=admin,dc=example,dc=org:insecure@openldap:389/dc=example,dc=org');
		$options->set(Options::ENABLED, true);
		$options->set(Options::FILTER, 'uid=%1$s');
		$options->set(Options::DEFAULT_ROLE, 'subscriber');
		$options->set(Options::DEBUG, true);
		$options->set(Options::NAME_ATTR, 'cn');

		exec(sprintf(
			'wp --allow-root option update --format=json authLDAPOptions \'%1$s\'',
			json_encode($options->toArray())
		));
	}

	/**
	 * @Given configuration value :arg1 is set to :arg2
	 */
	public function configurationValueIsSetTo($arg1, $arg2)
	{
		exec(sprintf(
			'wp --allow-root option patch update authLDAPOptions %1$s %2$s --format=json',
			$arg1,
			"'" . json_encode($arg2) . "'"
		));
	}

	/**
	 * @Given an LDAP user :arg1 with name :arg2, password :arg3 and email :arg4 exists
	 */
	public function anLdapUserWithNamePasswordAndEmailExists($arg1, $arg2, $arg3, $arg4)
	{
		exec(sprintf(
			'ldapadd -x -H %1$s -D "%2$s" -w %3$s <<LDIF
%4$s
LDIF',
			'ldap://openldap',
			'cn=admin,dc=example,dc=org',
			'insecure',
			<<<LDIF
			dn: uid=$arg1,dc=example,dc=org
			objectClass: inetOrgPerson
			objectClass: organizationalPerson
			objectClass: person
			objectClass: top
			objectClass: simpleSecurityObject
			uid: $arg1
			cn: $arg2
			sn: $arg2
			userPassword: $arg3
			mail: $arg4
			LDIF
		));
		exec(sprintf(
			'ldappasswd -H ldap://openldap:389 -x -D "uid=admin,dc=example,dc=org" -w "%3$s" -s "%2$s" "uid=%1$s,dc=example,dc=org"',
			$arg1,
			$arg3,
			'insecure'
		));
	}

	/**
	 * @Given an LDAP group :arg1 exists
	 */
	public function anLdapGroupExists($arg1)
	{
		exec(sprintf(
			'ldapadd -x -H %1$s -D "%2$s" -w %3$s <<LDIF
%4$s
LDIF',
			'ldap://openldap',
			'cn=admin,dc=example,dc=org',
			'insecure',
			<<<LDIF
			dn: cn=$arg1,dc=example,dc=org
			objectClass: groupOfUniqueNames
			cn: $arg1
			uniqueMember: cn=admin,dc=example,dc=org
			LDIF
		));
	}

	/**
	 * @Given a WordPress user :arg1 with name :arg2 and email :arg3 exists
	 */
	public function aWordpressUserWithNameAndEmailExists($arg1, $arg2, $arg3)
	{
		exec(sprintf(
			'wp --allow-root user create %1$s %3$s --display_name=%2$s --porcelain',
			$arg1,
			$arg2,
			$arg3
		));
	}

	/**
	 * @Given a WordPress role :arg1 exists
	 */
	public function aWordpressRoleExists($arg1)
	{
		exec(sprintf(
			'wp --allow-root role create %1$s %1$s',
			$arg1,
		));
	}

	/**
	 * @Given WordPress user :arg1 has role :arg2
	 */
	public function wordpressUserHasRole($arg1, $arg2)
	{
		exec(sprintf(
			'wp --allow-root user add-role %1$s %2$s',
			$arg1,
			$arg2
		));
	}

	/**
	 * @When LDAP user :arg1 logs in with password :arg2
	 */
	public function ldapUserLogsInWithPassword($arg1, $arg2)
	{
		//  curl -i 'http://localhost/wp-login.php' -X POST -H 'Cookie: wordpress_test_cookie=test' --data-raw 'log=localadmin&pwd=P%40ssw0rd'
		$client = new Client();

		$this->res = $client->post('http://wp/wp-login.php', [
			'cookies' => CookieJar::fromArray([
				'wordpress_test_cookie' => 'test',
				'XDEBUG_SESSION' => 'PHPSTORM',
			], 'http://wp'),
			'form_params' => [
				'log' => $arg1,
				'pwd' => $arg2,
			],
			'allow_redirects' => false
		]);
	}

	/**
	 * @Then the login suceeds
	 */
	public function theLoginSuceeds()
	{
		Assert::isInstanceOf($this->res, Response::class);
		Assert::eq( $this->res->getStatusCode(), 302);
		Assert::startsWith($this->res->getHeader('Location')[0], 'http://localhost/wp-admin');
	}

	/**
	 * @Then a new WordPress user :arg1 was created with name :arg2 and email :arg3
	 */
	public function aNewWordpressUserWasCreatedWithNameAndEmail($arg1, $arg2, $arg3)
	{
		exec(sprintf(
			'wp --allow-root user get %1$s --format=json 2> /dev/null',
			$arg1,
		), $output, $result);
		Assert::eq(0, $result);
		$user = json_decode($output[0], true);
		Assert::eq($user['user_email'], $arg3);
		Assert::eq($user['display_name'], $arg2);
		Assert::greaterThan(
			new DateTimeImmutable($user['user_registered']),
			(new DateTimeImmutable())->sub(new DateInterval('PT1M')),
		);
	}

	/**
	 * @Then the WordPress user :arg1 is member of role :arg2
	 */
	public function theWordpressUserIsMemberOfRole($arg1, $arg2)
	{
		exec(sprintf(
			'wp --allow-root user get %1$s --format=json 2> /dev/null',
			$arg1,
		), $output, $result);
		Assert::eq(0, $result);
		$user = json_decode($output[0], true);
		$roles = array_map(function($item): string {
			return trim($item);
		}, explode(',', $user['roles']));
		Assert::inArray($arg2, $roles);
	}

    /**
     * @Given LDAP user :arg1 is member of LDAP group :arg2
     */
    public function ldapUserIsMemberOfLdapGroup($arg1, $arg2)
    {
	    exec(sprintf(
		    'ldapmodify -x -H %1$s -D "%2$s" -w %3$s 2>&1 <<LDIF
%4$s
LDIF',
		    'ldap://openldap',
		    'cn=admin,dc=example,dc=org',
		    'insecure',
		    <<<LDIF
			dn: cn=$arg2,dc=example,dc=org
			changetype: modify
			add: uniqueMember
			uniqueMember: uid=$arg1,dc=example,dc=org
			LDIF
	    ));
	}

    /**
     * @Given a WordPress user :arg1 does not exist
     */
    public function aWordpressUserDoesNotExist($arg1)
    {
	    exec(sprintf(
		    'wp --allow-root user delete --yes %1$s',
		    $arg1,
	    ));
    }

    /**
     * @Given configuration value :arg1 is set to :arg2 and :arg3
     */
    public function configurationValueIsSetToAnd($arg1, $arg2, $arg3)
    {
		$roles = [];
		foreach ([$arg2, $arg3] as $arg) {
			$access = explode('=', $arg);
			$roles[$access[0]] = $access[1];
		}

		exec(sprintf(
			'echo %2$s | wp --allow-root option patch update authLDAPOptions %1$s --format=json',
			$arg1,
			"'" . json_encode($roles) . "'"
		), $result);
    }

    /**
     * @Then the WordPress user :arg1 is not member of role :arg2
     */
    public function theWordpressUserIsNotMemberOfRole($arg1, $arg2)
    {
		exec(sprintf(
			'wp --allow-root user get %1$s --format=json 2> /dev/null',
			$arg1,
		), $output, $result);
		Assert::eq(0, $result);
		$user = json_decode($output[0], true);
		$roles = array_map(function($item): string {
			return trim($item);
		}, explode(',', $user['roles']));
		Assert::false(in_array($arg2, $roles));

	}
}
