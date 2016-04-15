<?php

namespace AuthenticationBundle\Security;

use Symfony\Component\HttpFoundation\Cookie;
use AuthenticationBundle\Security\Encryption\EncryptionInterface;

/**
 * Produce a Cookie for authentication
 *
 * @author Jo Carter
 */
class CookieBuilder
{
    /**
     * Global coookie configuration (cookie 'name', 'lifetime')
     *
     * @var array
     */
    private $config;

    /**
     * @var EncryptionInterface
     */
    private $encryption;

    /**
     * Set up the cookie builder
     *
     * @param EncryptionInterface $encryption
     * @param array               $config     Global coookie configuration (cookie 'name', 'lifetime')
     */
    public function __construct(EncryptionInterface $encryption, $config)
    {
        $this->config     = $config;
        $this->encryption = $encryption;
    }

    /**
     * Produce the encrypted cookie
     *
     * @param array  $data   Information to encrypt (username, ip)
     * @param string $domain Domain to create the cookie for
     * @param bool   $secure Should the cookie be HTTPS only
     *
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    public function createCookie($data, $domain, $secure)
    {
        $expires         = time() + $this->config['lifetime'];
        $data['expires'] = ($this->config['lifetime'] > 0) ? $expires : null;
        $value           = $this->encryption->encryptData(json_encode($data));
        //$domain          = $this->extractMainDomain($domain); // @NOTE: So it works on server:run, we're not doing this

        $cookie = new Cookie(
            $this->config['name'],
            $value,
            $expires,
            '/', // path
            $domain,
            $secure,
            true // httponly
        );

        return $cookie;
    }

    /**
     * Ensure we get the main domain - so it will work on all subdomain sites
     *
     * @param Request $request
     *
     * @return string
     */
    private function extractMainDomain($domain)
    {
        $parts  = explode('.', $domain);

        if (count($parts) > 2) {
            $domain = explode('.', $domain, 2)[1];
        }

        return $domain;
    }
}
