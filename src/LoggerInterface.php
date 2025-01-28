<?php

namespace Org_Heigl\AuthLdap;

interface LoggerInterface
{
	public function log(string $message): void;
}
