<?php

namespace AuthenticationBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use AuthenticationBundle\Type\LoginType;

class DefaultController extends Controller
{
    /**
     * Render Login page
     *
     * @return Response
     */
    public function indexAction()
    {
        if ($this->get('security.authorization_checker')->isGranted('ROLE_USER')) {
            return new RedirectResponse($this->generateUrl('homepage'));
        }

        $authenticationUtils = $this->get('security.authentication_utils');
        $form                = $this->createForm(LoginType::class, ['username' => $authenticationUtils->getLastUsername()]);

        if ($authenticationUtils->getLastAuthenticationError()) {
            $form->addError(new FormError('Invalid username/ password'));
        }

        return $this->render('AuthenticationBundle:Default:index.html.twig', ['form' => $form->createView()]);
    }

    /**
     * Ensure cookies removed
     *
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function logoutAction(Request $request)
    {
        $secure   = $request->isSecure();
        $builder  = $this->get('cookie_builder');
        $cookie   = $builder->createCookie([], $request->getHost(), $secure);

        $response = new RedirectResponse($this->generateUrl('authentication_homepage'));
        $session  = $request->getSession();

        $session->invalidate();
        $response->headers->clearCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain(), $cookie->isSecure());

        return $response;
    }
}
