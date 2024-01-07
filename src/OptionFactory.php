<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licensed under the MIT-license. For details see the included file LICENSE.md
 */

declare(strict_types=1);

namespace Org_Heigl\AuthLdap;

use function json_decode;

class OptionFactory
{
	public function fromJson(string $json): Options
	{
		$option = new Options();
		$content = json_decode($json, true);
		foreach ($content as $key => $value) {
			$option->set($key, $value);
		}

		return $option;
	}
}
