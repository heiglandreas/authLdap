<?php

declare(strict_types=1);

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licensed under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdap\Exception;

use RuntimeException;

class UnknownOption extends RuntimeException
{
	public static function withKey(string $key): self
	{
		return new self(sprintf(
			'An option "%1$s" is not known',
			$key
		));
	}
}
