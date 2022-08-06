<?php

namespace SprayingLuck\Authenticator;

class SimpleAuth extends BaseAuthenticator
{
    public function __construct(string $issuer, string $user)
    {
        $data = [
            "secretLength"  => self::SECRET_LENGTH_SHORT,
            "codeLength"    => self::CODE_LENGTH_DEFAULT,
            "period"        => self::PERIOD_DEFAULT,
            "issuer"        => $issuer,
            "user"          => $user,
        ];
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