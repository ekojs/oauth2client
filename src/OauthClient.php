<?php declare(strict_types=1);

namespace OC\Library;

/**
 * Author: Eko Junaidi Salam <eko.junaidi.salam@gmail.com>
 * License: AGPL-3.0-or-later
 * 
 * Oauth2 Client Library
 */

use GuzzleHttp\Client;

class OauthClient {
    protected $authorizeURL;
    protected $tokenURL;
    protected $client_id;
    protected $client_secret;
    protected $callbackURL;

    public $client;
    public static $instance;

    public function __construct(){
		$this->client = new Client([
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
		]);
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function setClient(Client $client) {
        $this->client = $client;
        return $this;
    }

    public function setParameters(array $params){
        $this->authorizeURL = $params["authorizeURL"];
        $this->tokenURL = $params["tokenURL"];
        $this->client_id = $params["client_id"];
        $this->client_secret = $params["client_secret"];
        $this->callbackURL = $params["callbackURL"];
        return $this;
    }
    
    public function getAuthorization(string $scope="sso",?string $state=null,?string $code_verifiers=null): array {
        // Store generated random state and code challenge based on RFC 7636 
        // https://datatracker.ietf.org/doc/html/rfc7636#section-6.1
        $state = $state ?? state();
        list($code_verifier,$code_challenge) = codeChallenge($code_verifiers);

        $_SESSION['state'] = $state;
        $_SESSION['code_verifier'] = $code_verifier;
        $_SESSION['code_challenge'] = $code_challenge;
        
        $params = array(
            'response_type' => 'code',
            'client_id' => $this->client_id,
            'redirect_uri' => $this->callbackURL,
            'scope' => $scope,
            'state' => $state,
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256'
        );
        
        // header('Location: '.$this->authorizeURL.'?'.http_build_query($params));
        // die();

        return [
            "state" => $state,
            "code_verifier" => $code_verifier,
            "code_challenge" => $code_challenge,
            "location" => 'Location: '.$this->authorizeURL.'?'.http_build_query($params)
        ];
    }

    public function callback(array $params): array {
        if(!empty($params["error"])){
            \trigger_error($params["error"], \E_USER_ERROR);
        }

        $state = !empty($params['state']) ? $params['state'] : null;
        $code = !empty($params['code']) ? $params['code'] : null;

        if(!isset($code,$state)){
            \trigger_error("invalid_request", \E_USER_ERROR);
        }

        $stateSess = !empty($_SESSION['state']) ? $_SESSION['state'] : null;

        if(isset($state,$code)){
            if($state != $stateSess){
                \trigger_error("invalid_state", \E_USER_ERROR);
            }

            if(!ctype_xdigit($code)){
                \trigger_error("invalid_code", \E_USER_ERROR);
            }
            
            $creds = [
                'grant_type' => 'authorization_code',
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'redirect_uri' => $this->callbackURL,
                'code_verifier' => $_SESSION['code_verifier'],
                'code' => $code
            ];

            try{
                $res = $this->client->post($this->tokenURL,[
                    "form_params" => $creds
                ]);
                if($res->getStatusCode() == 200){
                    $body = (string) $res->getBody();
                    $token = json_decode($body,true);

                    if(!empty($token["error"])){
                        \trigger_error(json_encode($token), \E_USER_ERROR);
                    }

                    if(!empty($token["access_token"])){
                        unset($_SESSION['state']);
                        unset($_SESSION['code_verifier']);
                        unset($_SESSION['code_challenge']);
                        $_SESSION['access_token'] = $token['access_token'];
                        $_SESSION['refresh_token'] = $token['refresh_token'];
                        $_SESSION['scope'] = $token['scope'];
                        return $token;
                    }
                }
            }catch(\GuzzleHttp\Exception\ClientException $e){
                \trigger_error($e->getResponse()->getReasonPhrase(), \E_USER_ERROR);
            }
            \trigger_error("The user denies the request", \E_USER_ERROR);
        }
    }

    public function refreshToken(string $refresh_token): ?array {
        $creds = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'refresh_token' => $refresh_token
        ];

        try{
            $res = $this->client->post($this->tokenURL,[
                "form_params" => $creds
            ]);
            if($res->getStatusCode() == 200){
                $body = (string) $res->getBody();
                $token = json_decode($body,true);

                if(!empty($token["error"])){
                    \trigger_error(json_encode($token), \E_USER_ERROR);
                }

                if(!empty($token["access_token"])){
                    $_SESSION['access_token'] = $token['access_token'];
                    $_SESSION['refresh_token'] = $token['refresh_token'];
                    $_SESSION['scope'] = $token['scope'];
                    return $token;
                }
            }
        }catch(\GuzzleHttp\Exception\ClientException $e){
            \trigger_error($e->getResponse()->getReasonPhrase(), \E_USER_ERROR);
        }
        return null;
    }

    public function verify(string $token): bool{
        try{
            $res = $this->client->get(API_ENDPOINT."/oauth/verify",[
                "headers" => ["x-api-key" => $token]
            ]);
            if($res->getStatusCode() == 200){
                $body = (string) $res->getBody();
                $status = json_decode($body,true);

                if(!empty($status["error"])){
                    \trigger_error(json_encode($status), \E_USER_ERROR);
                }

                return $status["status"];
            }
        }catch(\GuzzleHttp\Exception\ClientException $e){
            \trigger_error($e->getResponse()->getReasonPhrase(), \E_USER_ERROR);
        }
        return false;
    }
}
