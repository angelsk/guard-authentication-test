<?php

namespace AuthenticationBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use AuthenticationBundle\Entity\ActiveDirectory;

/**
 * Specific user implementation to accomodate Active Directory
 *
 * @author Jo Carter
 */
class GuardUser implements AdvancedUserInterface, EquatableInterface
{
    /**
     * @var string
     */
    public $dn;

    /**
     * @var string
     */
    public $username;

    /**
     * @var array
     */
    public $roles = [];

    /**
     * @var ActiveDirectory
     */
    public $adObject;

    /**
     * Create new User
     *
     * @param string          $username
     * @param ActiveDirectory $adObject Active Directory object, may or may not be from the DB
     * @param array           $roles    Determine roles when finding and creating user
     */
    public function __construct($username, ActiveDirectory $adObject, $roles)
    {
        $this->username = $username;
        $this->dn       = $adObject->dn;
        $this->roles    = $roles;
        $this->adObject = $adObject;
    }

    /**
     * Returns the roles granted to the user.
     *
     * @return array The user roles
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * Returns the password used to authenticate the user.
     */
    public function getPassword()
    {
        return;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     * This can return null if the password was not encoded using a salt.
     */
    public function getSalt()
    {
        return;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials()
    {
        return;
    }

    /**
     * Checks whether the user's account has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw an AccountExpiredException and prevent login.
     *
     * @return bool true if the user's account is non expired, false otherwise
     *
     * @see Symfony\Component\Security\Core\Exception\AccountExpiredException
     */
    public function isAccountNonExpired()
    {
        return true;
    }

    /**
     * Checks whether the user is locked.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a LockedException and prevent login.
     *
     * @return bool true if the user is not locked, false otherwise
     *
     * @see Symfony\Component\Security\Core\Exception\LockedException
     */
    public function isAccountNonLocked()
    {
        return true;
    }

    /**
     * Checks whether the user's credentials (password) has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a CredentialsExpiredException and prevent login.
     *
     * @return bool true if the user's credentials are non expired, false otherwise
     *
     * @see Symfony\Component\Security\Core\Exception\CredentialsExpiredException
     */
    public function isCredentialsNonExpired()
    {
        return true;
    }

    /**
     * Checks whether the user is enabled.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a DisabledException and prevent login.
     *
     * @return bool true if the user is enabled, false otherwise
     *
     * @see Symfony\Component\Security\Core\Exception\DisabledException
     */
    public function isEnabled()
    {
        return $this->adObject->isDisabled === false;
    }

    /**
     * The equality comparison should neither be done by referential equality
     * nor by comparing identities (i.e. getId() === getId()).
     *
     * However, you do not need to compare every attribute, but only those that
     * are relevant for assessing whether re-authentication is required.
     *
     * Also implementation should consider that $user instance may implement
     * the extended user interface `AdvancedUserInterface`.
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof self) {
            return false;
        }

        if ($this->username != $user->username) {
            return false;
        }

        if ($this->dn != $user->dn) {
            return false;
        }

        return true;
    }
}
