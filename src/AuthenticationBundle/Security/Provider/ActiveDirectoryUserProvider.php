<?php

namespace AuthenticationBundle\Security\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use AuthenticationBundle\Security\GuardUser;
use AuthenticationBundle\Entity\Repository\ActiveDirectoryRepositoryInterface;

/**
 * Retrive a user from Active Directory
 *
 * @author Jo Carter
 */
class ActiveDirectoryUserProvider implements UserProviderInterface
{
    /**
     * @var ActiveDirectoryRepositoryInterface
     */
    private $adRepository;

    /**
     * @var RoleProviderInterface
     */
    private $roleProvider;

    /**
     * Construct the User Provider
     *
     * @param ActiveDirectoryRepositoryInterface $adRepository
     * @param RoleProviderInterface              $roleProvider
     */
    public function __construct(ActiveDirectoryRepositoryInterface $adRepository, RoleProviderInterface $roleProvider)
    {
        $this->adRepository = $adRepository;
        $this->roleProvider = $roleProvider;
    }

    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return UserInterface
     *
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByUsername($username)
    {
        if ('NONE_PROVIDED' === $username) {
            throw new UsernameNotFoundException('Username can not be null');
        }

        $adObject = $this->adRepository->findOneByUsername($username);

        if (!$adObject) {
            $exception = new UsernameNotFoundException('No user found with username');
            $exception->setUsername($username);

            throw $exception;
        }

        $roles = $this->roleProvider->determineRoles($adObject);
        $user  = new GuardUser($username, $adObject, $roles);

        return $user;
    }

    /**
     * Refreshes the user for the account interface.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @param UserInterface $user
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException if the account is not supported
     */
    public function refreshUser(UserInterface $user)
    {
        // This is used for storing authentication in the session but in this example, the token
        // is sent in each request, so authentication can be stateless. Throwing this exception
        // is proper to make things stateless
        throw new UnsupportedUserException('Refresh not supported');
    }

    /**
     * Whether this provider supports the given user class.
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass($class)
    {
        return 'AuthenticationBundle\Security\GuardUser' === $class;
    }
}
