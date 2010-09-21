<?php
/**
 * $Id: TestHelper.php 291905 2010-09-21 07:12:41Z heiglandreas $
 *
 * authLdap - Authenticate Wordpress against an LDAP-Backend.
 * Copyright (c) 2008 Andreas Heigl<andreas@heigl.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * This file contains basic configurations
 *
 * @category authLdap
 * @package authLdap
 * @subpackage tests
 * @author Andreas Heigl<andreas@heigl.org>
 * @copyright 2010 Andreas Heigl<andreas@heigl.org>
 * @license GPL
 * @since 21.09.2010
 */
/*
 * Include PHPUnit dependencies
 */
require_once 'PHPUnit/Framework/IncompleteTestError.php';
require_once 'PHPUnit/Framework/TestCase.php';
require_once 'PHPUnit/Framework/TestSuite.php';
require_once 'PHPUnit/Runner/Version.php';
require_once 'PHPUnit/TextUI/TestRunner.php';
require_once 'PHPUnit/Util/Filter.php';

/*
 * Set error reporting.
 */
error_reporting( E_ALL | E_STRICT );

/*
 * Determine the root, library, and tests directories of the authLdap
 * distribution.
 */
$root        = realpath(dirname(dirname(__FILE__)));
$coreLibrary = "$root";
$coreTests   = "$root/tests";

/*
 * Prepend the directories to the include_path.
 */
$path = array(
    $coreLibrary,
    $coreTests,
    get_include_path()
    );
set_include_path(implode(PATH_SEPARATOR, $path));

/*
 * Load the user-defined test configuration file, if it exists; otherwise, load
 * the default configuration.
 */
if (is_readable($coreTests . DIRECTORY_SEPARATOR . 'TestConfiguration.php')) {
    require_once $oreTests . DIRECTORY_SEPARATOR . 'TestConfiguration.php';
} else {
    require_once $coreTests . DIRECTORY_SEPARATOR . 'TestConfiguration.php.dist';
}

/**
 * Start output buffering, if enabled
 */
if (defined('TESTS_OB_ENABLED') && constant('TESTS_OB_ENABLED')) {
    ob_start();
}

/*
 * Unset global variables that are no longer needed.
 */
unset($root, $coreLibrary, $coreTests, $path);

