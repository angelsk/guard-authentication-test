<?php

namespace AuthenticationBundle\Security;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use AuthenticationBundle\Security\Encryption\EncryptionInterface;

/**
 * Validate the cookie built by the cookie builder
 *
 * @author Jo Carter
 */
class CookieValidator
{
    /**
     * @var EncryptionInterface
     */
    private $encryption;

    /**
     * Create cookie validator
     *
     * @param EncryptionInterface $encryption
     */
    public function __construct(EncryptionInterface $encryption)
    {
        $this->encryption = $encryption;
    }

    /**
     * Validate cookie
     *
     * @param string $cookieValue The encoded string from the cookie
     * @param string $ip          The client IP address
     *
     * @return string Username
     *
     * @throws \Symfony\Component\Security\Core\Exception\BadCredentialsException
     * @throws \Symfony\Component\Security\Core\Exception\CredentialsExpiredException
     */
    public function validateCookie($cookieValue, $ip)
    {
        try {
            $decryptedCookieValue = $this->encryption->decryptData($cookieValue);
        } catch (\InvalidArgumentException $e) {
            throw new BadCredentialsException('Cookie value was unable to be decrypted');
        }

        $data = json_decode($decryptedCookieValue, true);

        if (!$data) {
            throw new BadCredentialsException('Cookie value was not in the correct format');
        }

        if (!array_key_exists('username', $data) || !array_key_exists('ip', $data) || !array_key_exists('expires', $data)) {
            throw new BadCredentialsException('Cookie value did not include the expected data');
        }

        if ($data['ip'] != $ip) {
            throw new BadCredentialsException('IP address does not match cookie value');
        }

        if ($data['expires'] < time() || is_null($data['expires'])) {
            throw new CredentialsExpiredException('Cookie has expired');
        }

        return $data['username'];
    }
}
