<?php

namespace AuthenticationBundle\Security\Provider;

use AuthenticationBundle\Entity\ActiveDirectory;
use AuthenticationBundle\Services\Utilities\ActiveDirectoryHelper;

/**
 * Directly determine roles for a AD user
 *
 * @NOTE: Logic removed for test
 *
 * @author Jo Carter
 */
class ActiveDirectoryRoleProvider implements RoleProviderInterface
{
    /**
     * Determine the roles for an Active Directory object
     *
     * @param mixed $object
     *
     * @return array of roles
     */
    public function determineRoles($object)
    {
        if (!$object instanceof ActiveDirectory) {
            throw new \InvalidArgumentException('This particular role provider expects an Active Directory object');
        }

        $roles  = ['ROLE_USER'];

        return $roles;
    }
}
