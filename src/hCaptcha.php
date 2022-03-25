<?php

namespace HCaptcha;

use HCaptcha\Requests\CurlRequest;
use HCaptcha\Exceptions\RequestFormatException;
use HCaptcha\Requests\RequestInterface;
use HCaptcha\Responses\Response;

/**
 * Class hCaptcha
 *
 * @package hCaptcha
 */
class hCaptcha {
    const VERIFY_URL = 'https://hcaptcha.com/siteverify';

    /**
     * Personal hCaptcha secret key
     *
     * @var string $secretKey
     */
    protected $secretKey;

    /**
     * default hCaptcha site key, can be overrided on each request
     *
     * @var string $siteKey
     */
    protected $siteKey;

    /**
     * Request maker
     *
     * @var RequestInterface $request
     */
    protected $request;

    /**
     * hCaptcha constructor.
     *
     * @param string                $secretKey
     * @param RequestInterface|null $request
     *
     * @throws RequestFormatException
     */
    public function __construct($secretKey, $request = null) {
        $this->secretKey = $secretKey;
        $this->siteKey = null;

        if ($request) {
            if ($request instanceof RequestInterface) {
                $this->request = $request;
            } else {
                throw new RequestFormatException();
            }
        } else {
            $this->request = new CurlRequest();
        }
    }

    public function setSiteKey($siteKey) {
        $this->siteKey = $siteKey;
        return $this;
    }

    /**
     * @param string $response
     * @param null   $userIp
     *
     * @return Response
     */
    public function verify($response, $userIp = null, $siteKey = null) {
        $_siteKey = isset($siteKey) ? $siteKey : $this->siteKey;

        $response = $this->request->getResponse(
            self::VERIFY_URL,
            $this->secretKey,
            $response,
            $userIp,
            $_siteKey
        );

        return new Response($response);
    }

    public static function isSuccess($response, $secretKey, $userIp = null, $siteKey = null) {
        $hCaptcha = new static($secretKey);

        return $hCaptcha->verify($response, $userIp, $siteKey)->isSuccess();
    }
}
