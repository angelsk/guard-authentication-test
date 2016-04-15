<?php

namespace AuthenticationBundle\Security\Encryption;

/**
 * Interface for encryption
 *
 * @author Jo Carter
 */
interface EncryptionInterface
{
    /**
     * Encrypt the value
     *
     * @param string $value
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function encryptData($value);

    /**
     * Decrypt the value
     *
     * @param string $value
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function decryptData($value);
}
