<?php

/**
* Copyright Andrea Heigl <andreas@heigl.org>
 *
 * Licenses under the MIT-license. For details see the included file LICENSE.md
*/

namespace Org_Heigl\AuthLdap;

class LdapList
{
    /**
     * @var Ldap[]
     */
    protected $items = [];

    public function addLdap(Ldap $ldap)
    {
        $this->items[] = $ldap;
    }

    public function authenticate($username, $password, $filter = '(uid=%s)')
    {
        foreach ($this->items as $key => $item) {
            if (! $item->authenticate($username, $password, $filter)) {
                unset($this->items[$key]);
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

    public function search($filter, $attributes = array('uid'), $base = '')
    {
        foreach ($this->items as $item) {
            try {
                $result = $item->search($filter, $attributes, $base);
                return $result;
            } catch (Exception $e) {
                throw $e;
            }
        }

        throw new \AuthLDAP_Exception('No Results found');
    }
}
