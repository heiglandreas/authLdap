<?php
/**
 * $Id: AllTests.php 291905 2010-09-21 07:12:41Z heiglandreas $
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
 * This file tests the basic LDAP-Tasks
 *
 * @category authLdap
 * @package authLdap
 * @subpackage tests
 * @author Andreas Heigl<andreas@heigl.org>
 * @copyright 2010 Andreas Heigl<andreas@heigl.org>
 * @license GPL
 * @since 21.09.2010
 */

require_once 'TestHelper.php';
require_once 'LdapTest.php';

if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'AllTests::main');
}
/**
 * $Id: AllTests.php 291905 2010-09-21 07:12:41Z heiglandreas $
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
 * This file tests the basic LDAP-Tasks
 *
 * @category authLdap
 * @package authLdap
 * @subpackage tests
 * @author Andreas Heigl<andreas@heigl.org>
 * @copyright 2010 Andreas Heigl<andreas@heigl.org>
 * @license GPL
 * @since 21.09.2010
 */
class AllTests
{
    public static function main()
    {
        $parameters = array();

        if (TESTS_GENERATE_REPORT && extension_loaded('xdebug')) {
            $parameters['reportDirectory'] = TESTS_GENERATE_REPORT_TARGET;
        }

        PHPUnit_TextUI_TestRunner::run(self::suite(), $parameters);
    }

    /**
     * Regular suite
     *
     * All tests except those that require output buffering.
     *
     * @return PHPUnit_Framework_TestSuite
     */
    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('authLdap');

        $suite->addTestSuite('LdapTest');
        
        return $suite;
    }
}

if (PHPUnit_MAIN_METHOD == 'AllTests::main') {
    AllTests::main();
}
