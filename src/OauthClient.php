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
    protected $cookieDomain;
    protected $cookieToken;
    protected $cookieUrl;

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

    public function setParameters(array $params){
        $this->authorizeURL = $params["authorizeURL"];
        $this->tokenURL = $params["tokenURL"];
        $this->client_id = $params["client_id"];
        $this->client_secret = $params["client_secret"];
        $this->callbackURL = $params["callbackURL"];
        $this->cookieDomain = $params["cookieDomain"] ?? null;
        $this->cookieToken = $params["cookieToken"] ?? null;
        $this->cookieUrl = $params["cookieUrl"] ?? null;
        return $this;
    }
    
    public function getAuthorization(){
        $state = state();
        list($code_verifier,$code_challenge) = codeChallenge();

        // Store generated random state and code challenge based on RFC 7636 
        // https://datatracker.ietf.org/doc/html/rfc7636#section-6.1
        $_SESSION['state'] = $state;
        $_SESSION['code_verifier'] = $code_verifier;
        $_SESSION['code_challenge'] = $code_challenge;
        
        $params = array(
            'response_type' => 'code',
            'client_id' => $this->client_id,
            'redirect_uri' => $this->callbackURL,
            'scope' => 'user',
            'state' => $state,
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256'
        );
        
        header('Location: '.$this->authorizeURL.'?'.http_build_query($params));
        die();
    }

    public function callback($params){
        if(!empty($params["error"])){
            exit($params["error"]);
        }

        $state = !empty($params['state']) ? $params['state'] : null;
        $code = !empty($params['code']) ? $params['code'] : null;

        if(!isset($code,$state)){
            exit("invalid_request");
        }

        $stateSess = !empty($_SESSION['state']) ? $_SESSION['state'] : null;

        if(isset($state,$code)){
            if($state != $stateSess){
                exit("invalid_state");
            }

            if(empty($code)){
                exit("invalid_code");
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
                        exit(json_encode($token));
                    }

                    if(!empty($token["access_token"])){
                        unset($_SESSION['state']);
                        unset($_SESSION['code_verifier']);
                        unset($_SESSION['code_challenge']);
                        $_SESSION['access_token'] = $token['access_token'];
                        $_SESSION['refresh_token'] = $token['refresh_token'];
                        $_SESSION['scope'] = $token['scope'];
                        return $this;
                    }
                }
            }catch(\GuzzleHttp\Exception\ClientException $e){
                exit($e->getResponse()->getReasonPhrase());
            }
            exit("The user denies the request");
        }
    }

    public function getCookie(){
        if(!empty($_COOKIE[$this->cookieToken]) && 'NULL' !== $_COOKIE[$this->cookieToken]){
            try{
                $jar = \GuzzleHttp\Cookie\CookieJar::fromArray([$this->cookieToken => $_COOKIE[$this->cookieToken]],$this->cookieDomain);
                $res = $this->client->get($this->cookieUrl,['cookies' => $jar]);
                if($res->getStatusCode() == 200){
                    $body = (string) $res->getBody();
                    $token = json_decode($body,true);
                    $_SESSION['access_token'] = $token['access_token'];
                    $_SESSION['refresh_token'] = $token['refresh_token'] ?? null;
                    $_SESSION['scope'] = $token['scope'] ?? null;
                    return $this;
                }
            }catch(\GuzzleHttp\Exception\ClientException $e){
                exit($e->getResponse()->getReasonPhrase());
            }
        }
    }

    public function refreshToken($refresh_token){
        if(!empty($refresh_token)){
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
                        exit(json_encode($token));
                    }
    
                    if(!empty($token["access_token"])){
                        $_SESSION['access_token'] = $token['access_token'];
                        $_SESSION['refresh_token'] = $token['refresh_token'];
                        $_SESSION['scope'] = $token['scope'];
                        return $this;
                    }
                }
            }catch(\GuzzleHttp\Exception\ClientException $e){
                exit($e->getResponse()->getReasonPhrase());
            }
        }
    }
}
