<?php

namespace AuthenticationBundle\Services\Utilities;

use Symfony\Component\Ldap\LdapClient;

/**
 * To avoid unwieldy configuration, lets have a factory to create this.  Also will enable us
 * to switch out as needed
 *
 * @author Jo Carter
 */
class LdapClientFactory
{
    /**
     * Ldap Config - provides the appropriate parameters to create an LdapClient
     *
     * @var array
     */
    private $config;

    /**
     * Create the client factory
     *
     * @param array $config
     */
    public function __construct($config)
    {
        $this->config = $config;
    }

    /**
     * Create and return an Ldap Client
     *
     * @return LdapClient
     */
    public function createLdapClient()
    {
        // @NOTE: No config needed for test as doesn't actually connect
        $client = new LdapClient();

        return $client;
    }
}
