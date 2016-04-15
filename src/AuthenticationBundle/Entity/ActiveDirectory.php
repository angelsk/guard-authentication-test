<?php

namespace AuthenticationBundle\Entity;

/**
 * Object representing Active Directory user
 *
 * @author Jo Carter
 */
class ActiveDirectory
{
    /**
     * ObjectGUID - unique identifier from AD
     *
     * @var string
     */
    public $id;

    /**
     * @var string
     */
    public $dn;

    /**
     * @var string
     */
    public $fullName;

    /**
     * @var int
     */
    public $userAccountControl;

    /**
     * @var bool
     */
    public $isDisabled;

    /**
     * Create new object
     */
    public function __construct()
    {
    }
}
