<?php

declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

final class Logger implements LoggerInterface
{
	private $debug;

	/**
	 * @var false|resource
	 */
	private $fh = false;

	public function __construct(bool $debug = false)
	{
		$this->debug = $debug;
//		$this->fh = fopen('php://stderr', 'w');
	}
	public function log(string $message): void
	{
		if (! $this->debug) {
			return;
		}

		if ($this->fh !== false) {
			fwrite($this->fh, '[AuthLDAP] ' . $message . PHP_EOL);
		}
		error_log('[AuthLDAP] ' . $message, 0);
	}

	public function __destruct()
	{
		if ($this->fh === false) {
			return;
		}

		fclose($this->fh);
	}
}
