<?php

declare(strict_types=1);

/**
 * Copyright Andrea Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
 */

namespace Org_Heigl\AuthLdap\Exception;

use Exception;

class Error extends Exception
{
    public function __construct($message, $line = null)
    {
        parent::__construct($message);
        if ($line) {
            $this -> line = $line;
        }
    }
}
