<?php

namespace SprayingLuck\Authenticator;

class SecureAuth extends BaseAuthenticator
{
    public function __construct(string $issuer, string $user)
    {
        $data = [
            "secretLength"  => self::SECRET_LENGTH_LONG,
            "codeLength"    => self::CODE_LENGTH_EIGHT,
            "period"        => self::PERIOD_SHORT,
            "issuer"        => $issuer,
            "user"          => $user,
        ];
        parent::__construct($data);
    }

    public static function authenticate(
        string $secret,
        string $code,
        int $codeLength = self::CODE_LENGTH_EIGHT,
        int $period = self::PERIOD_SHORT
    ): bool
    {
        return parent::authenticate($secret, $code, $codeLength, $period);
    }

    public static function getTimeSlice(int $time, int $interval = self::PERIOD_SHORT, int $offset = 0): int
    {
        return parent::getTimeSlice($time, $interval, $offset);
    }

    public static function calculateCode(
        string $secret,
        int $codeLength = self::CODE_LENGTH_EIGHT,
        int $period = self::PERIOD_SHORT,
    ): string {
        return parent::calculateCode($secret, $codeLength, $period);
    }
}