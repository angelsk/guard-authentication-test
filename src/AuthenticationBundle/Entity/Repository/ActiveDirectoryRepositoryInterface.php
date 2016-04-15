<?php

namespace AuthenticationBundle\Entity\Repository;

use AuthenticationBundle\Entity\ActiveDirectory;

/**
 * Interface for AD repository
 *
 * @author Jo Carter
 */
interface ActiveDirectoryRepositoryInterface
{
    /**
     * Find user by username
     *
     * @param string $username
     *
     * @return ActiveDirectory
     */
    public function findOneByUsername($username);
}
