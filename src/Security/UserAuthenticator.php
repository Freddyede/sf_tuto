<?php

namespace App\Security;

use Exception;
use Symfony\Component\{
    HttpFoundation\RedirectResponse,
    HttpFoundation\Request,
    HttpFoundation\Response,
    Routing\Generator\UrlGeneratorInterface,
    Security\Core\Authentication\Token\TokenInterface,
    Security\Core\Security,
    Security\Http\Authenticator\AbstractLoginFormAuthenticator,
    Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge,
    Security\Http\Authenticator\Passport\Badge\UserBadge,
    Security\Http\Authenticator\Passport\Credentials\PasswordCredentials,
    Security\Http\Authenticator\Passport\Passport,
    Security\Http\Util\TargetPathTrait
};
use RuntimeException;

class UserAuthenticator extends AbstractLoginFormAuthenticator {
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(private readonly UrlGeneratorInterface $urlGenerator) { }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');

        $request->getSession()->set(Security::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
            ]
        );
    }

    /**
     * @throws Exception
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response {
        return match ($token->getUser()->getRoles()['roles']) {
            'ROLE_ADMIN' => new RedirectResponse($this->urlGenerator->generate('admin')),
            'ROLE_USER' => new RedirectResponse($this->urlGenerator->generate('profil')),
            default => throw new RuntimeException('Unexpected value'),
        };
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
