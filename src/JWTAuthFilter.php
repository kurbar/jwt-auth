<?php

namespace Tymon\JWTAuth;

use Illuminate\Events\Dispatcher;
use Symfony\Component\HttpFoundation\JsonResponse;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class JWTAuthFilter
{
    /**
     * @var \Illuminate\Events\Dispatcher
     */
    protected $events;

    /**
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;

    public function __construct(Dispatcher $events, JWTAuth $auth)
    {
        $this->events = $events;
        $this->auth = $auth;
    }

    /**
     * Filter the request
     *
     * @return \Illuminate\Http\Response
     */
    public function filter()
    {
        if (! $token = $this->auth->getToken()) {
            return $this->respond('tymon.jwt.absent', 'token_not_provided', 400);
        }

        try {
            $user = $this->auth->toUser($token);
        } catch (TokenExpiredException $e) {
            return $this->respond('tymon.jwt.expired', 'token_expired', $e->getStatusCode(), array($e));
        } catch (JWTException $e) {
            return $this->respond('tymon.jwt.invalid', 'token_invalid', $e->getStatusCode(), array($e));
        }

        if (! $user) {
            return $this->respond('tymon.jwt.user_not_found', 'user_not_found', 404);
        }

        $this->events->fire('tymon.jwt.valid', $user);
    }

    /**
     * Fire event and return the response
     *
     * @param  string   $event
     * @param  string   $error
     * @param  integer  $status
     * @param array $payload
     * @return mixed
     */
    protected function respond($event, $error, $status, $payload = array())
    {
        $response = $this->events->fire($event, $payload, true);

        return $response ?: new JsonResponse(array(
        	'status_code' => $status,
        	'message' => $error,
        ), $status);
    }
}
