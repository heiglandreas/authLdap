<?php

/**
 * Copyright (c) Andreas Heigl<andreas@heigl.org>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Andreas Heigl<andreas@heigl.org>
 * @copyright Andreas Heigl
 * @license   http://www.opensource.org/licenses/mit-license.php MIT-License
 * @since     19.07.2020
 * @link      http://github.com/heiglandreas/authLDAP
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

use Org_Heigl\AuthLdap\Exception\InvalidLdapUri;

use function array_map;
use function error_get_last;
use function getenv;
use function is_array;
use function is_string;
use function parse_url;
use function preg_replace_callback;
use function rawurlencode;
use function strlen;
use function strpos;
use function substr;
use function trim;
use function urldecode;

final class LdapUri
{
	private $server;

	private $scheme;

	private $port = 389;

	private string $baseDn;

	private $username = '';

	private $password = '';

	private function __construct(string $uri)
	{
		if (!preg_match('/^(ldap|ldaps|env)/', $uri)) {
			throw InvalidLdapUri::wrongSchema($uri);
		}

		if (strpos($uri, 'env:') === 0) {
			$newUri = getenv(substr($uri, 4));
			if (false === $newUri) {
				throw InvalidLdapUri::noEnvironmentVariableSet($uri);
			}
			$uri = (string) $newUri;
		}

		$uri = $this->injectEnvironmentVariables($uri);

		$array = parse_url($uri);
		if (!is_array($array)) {
			throw InvalidLdapUri::cannotparse($uri);
		}

		$url = array_map(static function ($item) {
			if (is_int($item)) {
				return $item;
			}
			return urldecode($item);
		}, $array);


		if (!isset($url['scheme'])) {
			throw InvalidLdapUri::noSchema($uri);
		}
		if (0 !== strpos($url['scheme'], 'ldap')) {
			throw InvalidLdapUri::wrongSchema($uri);
		}
		if (!isset($url['host'])) {
			throw InvalidLdapUri::noServerProvided($uri);
		}
		if (!isset($url['path'])) {
			throw InvalidLdapUri::noSearchBaseProvided($uri);
		}
		if (1 === strlen($url['path'])) {
			throw InvalidLdapUri::invalidSearchBaseProvided($uri);
		}

		$this->server = $url['host'];
		$this->scheme = $url['scheme'];
		$this->baseDn = substr($url['path'], 1);
		if (isset($url['user'])) {
			$this->username = $url['user'];
		}
		if ('' === trim($this->username)) {
			$this->username = 'anonymous';
		}
		if (isset($url['pass'])) {
			$this->password = $url['pass'];
		}
		if ($this->scheme === 'ldaps' && $this->port === 389) {
			$this->port = 636;
		}

		// When someone sets the port in the URL we overwrite whatever is set.
		// We have to assume they know what they are doing!
		if (isset($url['port'])) {
			$this->port = $url['port'];
		}
	}

	public static function fromString(string $uri): LdapUri
	{
		return new LdapUri($uri);
	}

	private function injectEnvironmentVariables(string $base): string
	{
		return preg_replace_callback('/%env:([^%]+)%/', static function (array $matches) {
			return rawurlencode(getenv($matches[1]));
		}, $base);
	}

	public function toString(): string
	{
		return $this->scheme . '://' . $this->server . ':' . $this->port;
	}

	public function __toString()
	{
		return $this->toString();
	}

	public function getUsername(): string
	{
		return $this->username;
	}

	public function getPassword(): string
	{
		return $this->password;
	}

	public function getBaseDn(): string
	{
		return $this->baseDn;
	}

	public function isAnonymous(): bool
	{
		if ($this->password === '') {
			return true;
		}

		if ($this->username === 'anonymous') {
			return true;
		}

		return false;
	}
}
