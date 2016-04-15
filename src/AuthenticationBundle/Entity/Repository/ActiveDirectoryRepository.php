<?php

namespace AuthenticationBundle\Entity\Repository;

use Symfony\Component\Ldap\LdapClient;
use AuthenticationBundle\Entity\ActiveDirectory;
use AuthenticationBundle\Entity\ActiveDirectoryFactory;
use AuthenticationBundle\Services\Utilities\LdapClientFactory;

/**
 * LDAP AD implementation
 *
 * @author Jo Carter
 */
class ActiveDirectoryRepository implements ActiveDirectoryRepositoryInterface
{
    /**
     * AD/ LDAP config for binding and searching for a user
     *
     * @var array
     */
    private $config;

    /**
     * @var LdapClient
     */
    private $ldapClient;

    /**
     * @var ActiveDirectoryFactory
     */
    private $adFactory;

    /**
     * Construct the User Provider
     *
     * @param array                  $config            Config for ldap
     * @param LdapClientFactory      $ldapClientFactory
     * @param ActiveDirectoryFactory $adFactory
     */
    public function __construct($config, LdapClientFactory $ldapClientFactory, ActiveDirectoryFactory $adFactory)
    {
        $this->config     = $config;
        $this->ldapClient = $ldapClientFactory->createLdapClient();
        $this->adFactory  = $adFactory;
    }

    /**
     * Find an Active Directory entry by username
     *
     * @param string $username
     *
     * @return ActiveDirectory|null
     *
     * @see \AuthenticationBundle\Entity\Repository\ActiveDirectoryRepositoryInterface::findOneByUsername()
     */
    public function findOneByUsername($username)
    {
        // @NOTE: Because we don't want to have to connect to active directory for a test
        $searchResult = [
            'objectguid'         => hex2bin('888b0af9530cc545cc228bff573fbe93'),
            'dn'                 => 'CN=Test User,OU=Development,OU=London,DC=jocarter,DC=co,DC=uk',
            'displayname'        => ['Test User'],
            'useraccountcontrol' => [512],
        ];

        $adObject = $this->adFactory->createActiveDirectoryFromAdDetails($searchResult);

        return $adObject;
    }
}
