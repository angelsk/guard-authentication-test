<?php

namespace AuthenticationBundle\Security\Authentication;

use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\ParameterBagUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Ldap\LdapClient;
use Symfony\Component\Ldap\Exception\ConnectionException;
use AuthenticationBundle\Security\CookieBuilder;
use AuthenticationBundle\Services\Utilities\LdapClientFactory;

/**
 * Authenticate a user (username and password) against Active Directory
 *
 * @author Jo Carter
 */
class ActiveDirectoryAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var LdapClient
     */
    private $ldapClient;

    /**
     * @var CookieBuilder
     */
    private $cookieBuilder;

    /**
     * Create AD authenticator.
     *
     * @param LdapClientFactory $ldapClientFactory
     * @param CookieBuilder     $cookieBuilder
     */
    public function __construct(LdapClientFactory $ldapClientFactory, CookieBuilder $cookieBuilder)
    {
        $this->ldapClient    = $ldapClientFactory->createLdapClient();
        $this->cookieBuilder = $cookieBuilder;
    }

    /**
     * Get the authentication credentials from the request and return them
     * as any type (e.g. an associate array). If you return null, authentication
     * will be skipped.
     * Whatever value you return here will be passed to getUser() and checkCredentials()
     *
     * @param Request $request
     *
     * @return mixed|null
     */
    public function getCredentials(Request $request)
    {
        // @NOTE: This is set as options normally, just hardcoded for test
        $username = trim(ParameterBagUtils::getParameterBagValue($request->request, 'login[username]'));
        $password = ParameterBagUtils::getParameterBagValue($request->request, 'login[password]');

        return [
            'username' => $username,
            'password' => $password
        ];
    }

    /**
     * Return a UserInterface object based on the credentials.
     * The *credentials* are the return value from getCredentials()
     * You may throw an AuthenticationException if you wish. If you return
     * null, then a UsernameNotFoundException is thrown for you.
     *
     * @param mixed                 $credentials
     * @param UserProviderInterface $userProvider
     *
     * @throws AuthenticationException
     *
     * @return UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (!$credentials['username'] || !$credentials['password']) {
            throw new AuthenticationException('Missing username and/or password');
        }

        return $userProvider->loadUserByUsername($credentials['username']);
    }

    /**
     * Returns true if the credentials are valid.
     *
     * If any value other than true is returned, authentication will
     * fail. You may also throw an AuthenticationException if you wish
     * to cause authentication to fail.
     *
     * The *credentials* are the return value from getCredentials()
     *
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     *
     * @throws AuthenticationException
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        // @NOTE: Allow any username and password for the test
        return true;
    }

    /**
     * Called when authentication executed, but failed (e.g. wrong username password).
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the login page or a 403 response.
     *
     * If you return null, the request will continue, but the user will
     * not be authenticated. This is probably not what you want to do.
     *
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return; // Just let the chain handle it
    }

    /**
     * Called when authentication executed and was successful!
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the last page they visited.
     *
     * If you return null, the current request will continue, and the user
     * will be authenticated. This makes sense, for example, with an API.
     *
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey The provider (i.e. firewall) key
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $secure = $request->isSecure();
        $domain = $request->getHost();
        $data   = [
            'username' => $token->getUsername(),
            'ip'       => $request->getClientIp()
        ];

        $response = new RedirectResponse('/'); // Can't use target_path as not set if stateless
        $cookie   = $this->cookieBuilder->createCookie($data, $domain, $secure);

        $response->headers->setCookie($cookie);

        return $response;
    }

    /**
     * Does this method support remember me cookies?
     *
     * Remember me cookie will be set if *all* of the following are met:
     *  A) This method returns true
     *  B) The remember_me key under your firewall is configured
     *  C) The "remember me" functionality is activated. This is usually
     *      done by having a _remember_me checkbox in your form, but
     *      can be configured by the "always_remember_me" and "remember_me_parameter"
     *      parameters under the "remember_me" firewall key
     *
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * Returns a response that directs the user to authenticate.
     *
     * This is called when an anonymous request accesses a resource that
     * requires authentication. The job of this method is to return some
     * response that "helps" the user start into the authentication process.
     *
     * Examples:
     *  A) For a form login, you might redirect to the login page
     *      return new RedirectResponse('/login');
     *  B) For an API token authentication system, you return a 401 response
     *      return new Response('Auth header required', 401);
     *
     * @param Request                 $request       The request that resulted in an AuthenticationException
     * @param AuthenticationException $authException The exception that started the authentication process
     *
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new Response('Authentication credentials not supplied', 401);
    }
}
