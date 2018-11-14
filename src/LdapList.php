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
 * @since     07.07.2016
 * @link      http://github.com/heiglandreas/authLDAP
 */

namespace Org_Heigl\AuthLdap;

class LdapList
{
    /**
     * @var \LDAP[]
     */
    protected $items = [];

    public function addLdap(LDAP $ldap)
    {
        $this->items[] = $ldap;
    }

    public function authenticate($username, $password, $filter = '(uid=%s)')
    {
        foreach ($this->items as $key => $item) {
            if (! $item->authenticate($username, $password, $filter)) {
                unset ($this->items[$key]);
                continue;
            }
            return true;
        }

        return false;
    }

    public function bind()
    {
        $allFailed = true;
        foreach ($this->items as $key => $item) {
            try {
                $item->bind();
            } catch (\Exception $e) {
                unset($this->items[$key]);
                continue;
            }
            $allFailed = false;
        }

        if ($allFailed) {
            throw new AuthLDAP_Exception('No bind successfull');
        }

        return true;
    }

    public function search($filter, $attributes = array('uid'))
    {
        foreach ($this->items as $item) {
            try {
                $result = $item->search($filter, $attributes);
                return $result;
            } catch (Exception $e) {
                throw $e;
            }
        }

        throw new \AuthLDAP_Exception('No Results found');
    }
}
