<?php

namespace AuthenticationBundle\Security\Encryption;

/**
 * Encrypt cookie data
 *
 * @NOTE: This is NOT encryption - just base64 encoded for the test
 *
 * @author Jo Carter
 */
class Encryption implements EncryptionInterface
{
    /**
     * Encrypt data
     *
     * @param string $value
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @see \AuthenticationBundle\Security\EncryptionInterface::encryptData()
     */
    public function encryptData($value)
    {
        if (!$value) {
            throw new \InvalidArgumentException('$value to be encrypted cannot be empty');
        }

        $encryptedText = base64_encode($value);

        return $encryptedText;
    }

    /**
     * Decrypt data
     *
     * @param string $value
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @see \AuthenticationBundle\Security\EncryptionInterface::decryptData()
     */
    public function decryptData($value)
    {
        if (!$value) {
            throw new \InvalidArgumentException('$value to be decrypted cannot be empty');
        }

        $decryptedText = base64_decode($value);

        return $decryptedText;
    }
}
