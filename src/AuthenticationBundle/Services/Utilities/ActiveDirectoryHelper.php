<?php

namespace AuthenticationBundle\Services\Utilities;

/**
 * Some useful helpers for Active Directory objects that are not specific to any functionality
 *
 * @author Jo Carter
 */
class ActiveDirectoryHelper
{
    /**
     * Active Directory account flag values
     *
     * @see https://support.microsoft.com/en-us/kb/305144
     */
    const SCRIPT                         = 1;
    const ACCOUNTDISABLE                 = 2;
    const HOMEDIR_REQUIRED               = 8;
    const LOCKOUT                        = 16;
    const PASSWD_NOTREQD                 = 32;
    const PASSWD_CANT_CHANGE             = 64;
    const ENCRYPTED_TEXT_PWD_ALLOWED     = 128;
    const TEMP_DUPLICATE_ACCOUNT         = 256;
    const NORMAL_ACCOUNT                 = 512;
    const INTERDOMAIN_TRUST_ACCOUNT      = 2048;
    const WORKSTATION_TRUST_ACCOUNT      = 4096;
    const SERVER_TRUST_ACCOUNT           = 8192;
    const DONT_EXPIRE_PASSWORD           = 65536;
    const MNS_LOGON_ACCOUNT              = 131072;
    const SMARTCARD_REQUIRED             = 262144;
    const TRUSTED_FOR_DELEGATION         = 524288;
    const NOT_DELEGATED                  = 1048576;
    const USE_DES_KEY_ONLY               = 2097152;
    const DONT_REQ_PREAUTH               = 4194304;
    const PASSWORD_EXPIRED               = 8388608;
    const TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216;
    const PARTIAL_SECRETS_ACCOUNT        = 67108864;

    /**
     * Determine if a flag is set for disabled accounts.
     * Specific method because this will be used frequently.
     *
     * @param string $userAccountControl Bitmask value from $ad['useraccountcontrol']
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isAccountDisabled($userAccountControl)
    {
        if (is_null($userAccountControl)) {
            throw new \InvalidArgumentException('Did not provide valid $userAccountControl to determine flags from');
        }

        $flag   = self::ACCOUNTDISABLE;
        $result = self::isFlagSet($flag, $userAccountControl);

        return $result === $flag;
    }

    /**
     * Determine whether a flag is set or not using a bitwise/bitmask operation.
     *
     * @param int $flag
     * @param int $value
     *
     * @see http://php.net/manual/en/language.operators.bitwise.php
     *
     * @return int If the flag is set it will return the value of the flag; if not then 0
     *
     * @throws \InvalidArgumentException
     */
    public function isFlagSet($flag, $value)
    {
        if (is_null($value)) {
            throw new \InvalidArgumentException('Did not provide valid $value to determine flags from');
        }

        return $value & $flag;
    }

    /**
     * Convert binary objectGUID from Active Directory to a string
     *
     * @param data string $binaryValue
     *
     * @return string
     */
    public function convertObjectGuid($binaryValue)
    {
        $hexValue    = unpack('H*hex', $binaryValue);
        $hex         = $hexValue['hex'];
        $hex1        = substr($hex, -26, 2).substr($hex, -28, 2).substr($hex, -30, 2).substr($hex, -32, 2);
        $hex2        = substr($hex, -22, 2).substr($hex, -24, 2);
        $hex3        = substr($hex, -18, 2).substr($hex, -20, 2);
        $hex4        = substr($hex, -16, 4);
        $hex5        = substr($hex, -12, 12);
        $stringValue = sprintf('%s-%s-%s-%s-%s', $hex1, $hex2, $hex3, $hex4, $hex5);

        return $stringValue;
    }
}
