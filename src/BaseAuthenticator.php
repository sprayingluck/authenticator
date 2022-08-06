<?php

namespace SprayingLuck\Authenticator;

use Base32\Base32;
use Exception;
use InvalidArgumentException;

class BaseAuthenticator
{
    protected const BASE_32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    protected const SECRET_LENGTH_SHORT = 16;
    protected const SECRET_LENGTH_DEFAULT = 32;
    protected const SECRET_LENGTH_LONG = 64;

    // VALID OPTIONS FOR CODE LENGTH
    const CODE_LENGTH_DEFAULT = 6;
    const CODE_LENGTH_SEVEN = 7;
    const CODE_LENGTH_EIGHT = 8;
    const VALID_CODE_LENGTHS = [
        self::CODE_LENGTH_DEFAULT,
        self::CODE_LENGTH_SEVEN,
        self::CODE_LENGTH_EIGHT,
    ];

    // VALID OPTIONS FOR PERIOD
    const PERIOD_SHORT = 15;
    const PERIOD_DEFAULT = 30;
    const PERIOD_LONG = 60;
    const VALID_PERIODS = [
        self::PERIOD_SHORT,
        self::PERIOD_DEFAULT,
        self::PERIOD_LONG,
    ];

    // DEFAULT constRUCTOR PARAM FORMAT
    const DEFAULT_PARAM_FORMAT = [
        "secretLength"  => self::SECRET_LENGTH_DEFAULT,
        "codeLength"    => self::CODE_LENGTH_DEFAULT,
        "period"        => self::PERIOD_DEFAULT,
        "issuer"        => "Default Issuer",
        "user"          => "Default User",
    ];


    // USER SPECIFIC PARAMETERS
    protected int $secretLength = self::SECRET_LENGTH_DEFAULT;
    protected int $codeLength = self::CODE_LENGTH_DEFAULT;
    protected int $period = self::PERIOD_DEFAULT;
    protected string $issuer;
    protected string $user;
    protected string $secret;


    /**
     * Instantiate the Authenticator object.
     *
     * @param array $options
     * @throws Exception
     */
    public function __construct(array $options)
    {
        self::validated($options);
        $this->generateSecret();
    }

    /**
     * Validate if the provided parameters are valid.
     *
     * @param array $options
     * @return void
     */
    protected function validated(array $options): void
    {
        $this->secretLength = $options['secretLength'] ?? self::SECRET_LENGTH_DEFAULT;
        $this->codeLength = $options['codeLength'] ?? self::CODE_LENGTH_DEFAULT;
        $this->period = $options['period'] ?? self::PERIOD_DEFAULT;
        $this->issuer = $options['issuer'] ?? null;
        $this->user = $options['user'] ?? null;

        // checking if the secret length is valid
        if ($this->secretLength == 0 || $this->secretLength % 8 > 0) {
            throw new InvalidArgumentException("Secret length must be longer than 0 and divisible by 8.");
        }

        // checking if the code length is valid
        if (!in_array($this->codeLength, self::VALID_CODE_LENGTHS)) {
            $m = "Code length must be either " . implode(", ", self::VALID_CODE_LENGTHS) . " digits.";
            throw new InvalidArgumentException($m);
        }

        // checking if the period is valid
        if (!in_array($this->period, self::VALID_PERIODS)) {
            $m = "Period must be either " . implode(", ", self::VALID_PERIODS) . " seconds.";
            throw new InvalidArgumentException($m);
        }

        // checking if the issuer and user param is provided
        if (!$this->issuer || !$this->user) {
            throw new InvalidArgumentException("Issuer and user are required.");
        }

        // check if the provided issuer is valid
        if (str_contains($this->issuer, ":")) {
            throw new InvalidArgumentException("Colon is not allowed in the 'issuer' parameter.");
        }

        // check if the provided user is valid
        if (str_contains($this->user, ":")) {
            throw new InvalidArgumentException("Colon is not allowed in the 'user' parameter.");
        }
    }

    /**
     * Generating a random secret key and set the attribute.
     * Accepts customised secret length. (must be multiple of 8)
     *
     * @return void
     * @throws Exception
     */
    protected function generateSecret(): void
    {
        $key = '';
        while (strlen($key) < $this->secretLength) {
            $key .= self::BASE_32_CHARS[random_int(0, 31)];
        }

        $this->secret = $key;
    }

    /**
     * Get the label of this authenticator.
     * Eg: SprayingLuck (user)
     *
     * @return string
     */
    public function getLabel(): string
    {
        return $this->issuer . " ($this->user)";
    }

    /**
     * Get the secret key attribute.
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Generating the OTP Auth string.
     * Using TOTP.
     *
     * @return string
     */
    public function generateOTPAuth(): string
    {
        $uri = "otpauth://totp/";
        $uri .= rawurlencode($this->getLabel());
        $uri .= "?secret=" . $this->getSecret();
        $uri .= "&issuer=" . rawurlencode($this->issuer);
        $uri .= "&digits=" . $this->codeLength;
        $uri .= "&period=" . $this->period;
        return $uri;
    }

    /**
     * Generating the QR code image.
     *
     * @param int $size
     * @return string
     */
    public function generateQRCode(int $size = 300): string
    {
        // TODO: implement local QR generator
        return "https://chart.googleapis.com/chart?chs={$size}x{$size}&chld=M|0&cht=qr&chl=".$this->generateOTPAuth();
    }

    /**
     * Authenticating the OTP code.
     *
     * @param string $secret
     * @param string $code
     * @param int $codeLength
     * @param int $period
     * @return bool
     */
    public static function authenticate(
        string $secret,
        string $code,
        int $codeLength = self::CODE_LENGTH_DEFAULT,
        int $period = self::PERIOD_DEFAULT,
    ): bool
    {
        return self::calculateCode($secret, $codeLength, $period) == $code;
    }

    /**
     * Calculate the current time slice.
     *
     * @param int $time (current Unix timestamp)
     * @param int $interval
     * @param int $offset
     * @return int
     */
    public static function getTimeSlice(int $time, int $interval = self::PERIOD_DEFAULT, int $offset = 0): int
    {
        return floor($time / $interval) + $offset;
    }

    /**
     * Calculate a code for the given secret key.
     *
     * @param string $secret
     * @param int $period
     * @param int $codeLength
     * @return string
     */
    public static function calculateCode(
        string $secret,
        int $codeLength = self::CODE_LENGTH_DEFAULT,
        int $period = self::PERIOD_DEFAULT,
    ): string
    {
        if (!in_array($codeLength, self::VALID_CODE_LENGTHS) || !in_array($period, self::VALID_PERIODS)) {
            throw new InvalidArgumentException("Invalid code length or period.");
        }

        $timeSlice = self::getTimeSlice(time(), $period);

        // Packs the times lice as an "unsigned long"
        // "N": always 32 bit, big endian byte order
        $timeSlice = pack("N", $timeSlice);

        // Then pad it with the null terminator
        // chr(0) == ASCII null
        $timeSlice = str_pad($timeSlice, 8, chr(0), STR_PAD_LEFT);

        // Hash it with SHA1. The spec does offer the idea of other algorithms,
        // but notes that the authenticator is currently ignoring it...
        $hash = hash_hmac("SHA1", $timeSlice, Base32::decode($secret), true);

        // Last 4 bits are an offset apparently
        $offset = ord(substr($hash, -1)) & 0x0F;

        // Grab the last 4 bytes
        $result = substr($hash, $offset, 4);

        // Unpack it again
        $value = unpack('N', $result)[1];

        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        // Modulo down to the right number of digits
        $modulo = pow(10, $codeLength);

        // Finally, pad out the string with 0s
        return str_pad($value % $modulo, $codeLength, '0', STR_PAD_LEFT);
    }
}