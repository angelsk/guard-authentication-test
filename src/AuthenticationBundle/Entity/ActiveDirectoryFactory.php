<?php

namespace AuthenticationBundle\Entity;

use AuthenticationBundle\Services\Utilities\ActiveDirectoryHelper;

/**
 * Create ActiveDirectory object
 *
 * @author Jo Carter
 */
class ActiveDirectoryFactory
{
    /**
     * @var ActiveDirectoryHelper
     */
    private $helper;

    /**
     * Need the Helper to be able to create ActiveDirectory object with correct parameters
     *
     * @param ActiveDirectoryHelper $helper
     */
    public function __construct(ActiveDirectoryHelper $helper)
    {
        $this->helper = $helper;
    }

    /**
     * Create a new ActiveDirectory object from AD/LDAP details
     *
     * @param array $adDetails
     *
     * @return ActiveDirectory
     */
    public function createActiveDirectoryFromAdDetails($adDetails)
    {
        $activeDirectory = new ActiveDirectory();

        $activeDirectory->id                 = $this->helper->convertObjectGuid($adDetails['objectguid'][0]);
        $activeDirectory->dn                 = $adDetails['dn'];
        $activeDirectory->userAccountControl = $adDetails['useraccountcontrol'][0];
        $activeDirectory->fullName           = (isset($adDetails['displayname']) ? $adDetails['displayname'][0] : null);
        $activeDirectory->isDisabled         = $this->helper->isAccountDisabled($activeDirectory->userAccountControl);

        return $activeDirectory;
    }
}
