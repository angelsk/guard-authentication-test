<?php

namespace AuthenticationBundle\Security\Authentication;

use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Symfony\Component\HttpFoundation\Request;
use AuthenticationBundle\Security\CookieValidator;

/**
 * This is used by the security filter to try and validate an authentication cookie
 *
 * On auth failure it falls back to the default Symfony behaviour
 *
 * @author Jo Carter
 */
class SimpleCookieAuthenticator implements SimplePreAuthenticatorInterface
{
    /**
     * Global coookie configuration (cookie 'name', 'lifetime')
     *
     * @var array
     */
    private $config;

    /**
     * @var CookieValidator
     */
    private $cookieValidator;

    /**
     * Create CookieAuthenticator
     *
     * @param array           $config          Global coookie configuration (cookie 'name', 'lifetime')
     * @param CookieValidator $cookieValidator
     */
    public function __construct($config, CookieValidator $cookieValidator)
    {
        $this->config          = $config;
        $this->cookieValidator = $cookieValidator;
    }

    /**
     * Early in the request cycle, Symfony calls this method.
     * It creates a token object that contains all of the information from the request that you need to
     * authenticate the user (e.g: the access_token header).
     * If that information is missing, throwing a BadCredentialsException will cause authentication to fail
     *
     * @see SimplePreAuthenticatorInterface::createToken()
     *
     * @param Request $request
     * @param string  $providerKey
     *
     * @throws AuthenticationCredentialsNotFoundException
     *
     * @return PreAuthenticatedToken
     */
    public function createToken(Request $request, $providerKey)
    {
        $cookie = $request->cookies->get($this->config['name']);

        if (is_null($cookie)) {
            throw new AuthenticationCredentialsNotFoundException('No Auth Cookie found');
        }

        $token  = new PreAuthenticatedToken(
            'anon.', // not yet authenticated
            [
                // Ensures that cookie decoded correctly from the header; won't futz with the +s
                'cookie' => rawurldecode($cookie),
                'ip'     => $request->getClientIp()
            ],
            $providerKey,
            [] // no roles
        );

        return $token;
    }

    /**
     * After symfony calls createToken(), it will then call this method on this class (and any other
     * authentication listeners) to figure out who should handle the token.
     * This allows several authentication mechanisms to be used for the same firewall (so you can fall
     * back to login if authentication fails)
     *
     * @see \Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface::supportsToken()
     *
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return bool
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return ($token instanceof PreAuthenticatedToken) && ($providerKey === $token->getProviderKey());
    }

    /**
     * If supportsToken() returns true, symfony will now call this method.
     * One key part is the $userProvider, which is an external class that helps you load information about
     * the user.
     *
     * @see SimpleAuthenticatorInterface::authenticateToken()
     *
     * @param TokenInterface        $token
     * @param UserProviderInterface $userProvider
     * @param string                $providerKey
     *
     * @throws BadCredentialsException
     * @throws CredentialsExpiredException
     *
     * @return PreAuthenticatedToken
     */
    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        $credentials = $token->getCredentials();

        try {
            $username = $this->cookieValidator->validateCookie($credentials['cookie'], $credentials['ip']);
        } catch (AuthenticationException $e) {
            $e->setToken($token);

            throw $e;
        }

        $user = $userProvider->loadUserByUsername($username);

        return new PreAuthenticatedToken(
            $user,
            $credentials,
            $providerKey,
            $user->getRoles()
        );
    }
}
