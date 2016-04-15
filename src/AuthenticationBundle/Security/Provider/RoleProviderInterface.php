<?php

namespace AuthenticationBundle\Security\Provider;

/**
 * Interface for role provider, so can have different implementations
 *
 * @author Jo Carter
 */
interface RoleProviderInterface
{
    /**
     * Determine the roles for an object/ user
     *
     * @param mixed $object
     *
     * @return array of roles
     */
    public function determineRoles($object);
}
