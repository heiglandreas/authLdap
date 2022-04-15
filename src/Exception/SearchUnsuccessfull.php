<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap\Exception;

use RuntimeException;

class SearchUnsuccessfull extends RuntimeException
{
	public static function fromSearchFilter(string $filter): self
	{
		return new self(sprintf(
			'Search for %1$s was not successfull',
			$filter
		));
	}
}
