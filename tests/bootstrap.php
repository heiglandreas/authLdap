<?php

/**
 * Copyright Andreas Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

require_once __DIR__ . '/../vendor/autoload.php'; // adjust the path as needed

if (! is_dir(__DIR__ . '/../wordpress/wp-content')) {
	mkdir(__DIR__ . '/../wordpress/wp-content', 0777);
}
\WorDBless\Load::load();
