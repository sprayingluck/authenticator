<?php

namespace SprayingLuck\Authenticator;

class DefaultAuth extends BaseAuthenticator
{
    public function __construct(string $issuer, string $user)
    {
        $data = self::DEFAULT_PARAM_FORMAT;
        $data['issuer'] = $issuer;
        $data['user'] = $user;
        parent::__construct($data);
    }

    public static function authenticate(
        string $secret,
        string $code,
        int $codeLength = self::CODE_LENGTH_DEFAULT,
        int $period = self::PERIOD_DEFAULT
    ): bool
    {
        return parent::authenticate($secret, $code, $codeLength, $period);
    }
}