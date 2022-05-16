<?php declare(strict_types=1);

namespace OC\Tests;

use PHPUnit\Framework\TestCase;
use OC\Library\OauthClient;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\BadResponseException;

class OauthClientTest extends TestCase {

    private $oc;
    private $params;
    private $codeVerifier = "br852dc1gwvRyMqfJth86GNYDMvQ5il9EA65Rg1lmoPJXgWDia3sPOtKOwl4qQXFO8gbgA5UA~2rB0LLeBYW28PqDT~ChgtNVmu_hsRuGVvZSdiyMqdCXzuxupoqA9AT";
    private $codeChallenge = "1I50RLhjYVfXkX96X43JxEnK8HH_uxJnBZUFGq5kOh4";

    protected function setUp(): void
    {
        parent::setUp();
        if (!defined("API_ENDPOINT")) {
            define("API_ENDPOINT","https://dev.api.com");
        }
        $this->params = [
            "authorizeURL" => "https://dev.api.com/authorize",
            "tokenURL" => "https://dev.api.com/oauth/token",
            "client_id" => "12345",
            "client_secret" => "clientsecret@1234567890",
            "callbackURL" => "https://my.app.com/callback",
        ];
        $this->oc = OauthClient::getInstance();
        $this->oc->setParameters($this->params);
    }
    
    public function testGetAuthorization(): void
    {
        $this->assertIsArray($this->oc->getAuthorization());
        $this->assertEqualsCanonicalizing([
            "state" => "12345",
            "code_verifier" => $this->codeVerifier,
            "code_challenge" => $this->codeChallenge,
            "location" => 'Location: '.$this->params["authorizeURL"].'?'.http_build_query([
                'response_type' => 'code',
                'client_id' => $this->params["client_id"],
                'redirect_uri' => $this->params["callbackURL"],
                'scope' => "sso",
                'state' => "12345",
                'code_challenge' => $this->codeChallenge,
                'code_challenge_method' => 'S256'
            ])
        ],$this->oc->getAuthorization("sso","12345",$this->codeVerifier));
    }

    public function testCallbackNullError(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/Too few arguments/");
        $this->oc->callback();
    }

    public function testCallbackError(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/Undefined Error/");
        $this->oc->callback(["error" => "Undefined Error"]);
    }

    public function testCallbackInvalidRequest(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/invalid_request/");
        $this->oc->callback(["code" => null]);
    }

    public function testCallbackInvalidState(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/invalid_state/");
        $this->oc->callback(["state" => "12345s","code" => "12345"]);
    }

    public function testCallbackInvalidCode(): void 
    {
        $_SESSION["state"] = "12345";
        $this->expectError();
        $this->expectErrorMessageMatches("/invalid_code/");
        $this->oc->callback(["state" => "12345","code" => "Gulih123"]);
    }

    public function testCallbackUserDeniesRequest(): void 
    {
        $_SESSION["state"] = "12345";
        $_SESSION['code_verifier'] = $this->codeVerifier;
        $this->expectError();
        $this->expectErrorMessageMatches("/The user denies the request/");

        $mock = new MockHandler([
            new Response(401)
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->oc->callback(["state" => "12345","code" => "12345abcdef"]);
    }

    public function testCallbackException(): void 
    {
        $_SESSION["state"] = "12345";
        $_SESSION['code_verifier'] = $this->codeVerifier;
        $this->expectError();
        $this->expectErrorMessageMatches("/Unauthorized/");

        $mock = new MockHandler([
            new Response(401)
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => true,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->oc->callback(["state" => "12345","code" => "12345abcdef"]);
    }

    public function testCallbackTokenError(): void 
    {
        $_SESSION["state"] = "12345";
        $_SESSION['code_verifier'] = $this->codeVerifier;
        $this->expectError();
        $this->expectErrorMessageMatches("/something error/");

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{ "error": "something error"}')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->oc->callback(["state" => "12345","code" => "12345abcdef"]);
    }

    public function testCallbackValid(): void 
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{ "access_token": "token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh_token", "scope": "sso" }')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $_SESSION["state"] = "12345";
        $this->assertEquals('{"access_token":"token","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh_token","scope":"sso"}',json_encode($this->oc->callback(["state" => "12345","code" => "12345abcdef"])));
    }

    public function testRefreshTokenError(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/Too few arguments/");
        $this->oc->refreshToken();
    }

    public function testRefreshTokenNull(): void 
    {
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(401)
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->assertNull($this->oc->refreshToken("mytoken"));
    }

    public function testRefreshTokenException(): void 
    {
        // $this->expectException(RequestException::class);
        $this->expectError();
        $this->expectErrorMessageMatches("/Unauthorized/");
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(401)
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => true,
			'verify' => false
        ]);

        $this->oc->setClient($client);
        $this->oc->refreshToken("mytoken");
    }

    public function testRefreshTokenErrorResponse(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/something wrong/");
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{ "error": "something wrong"}')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->oc->refreshToken("mytoken");
    }

    public function testRefreshTokenValid(): void 
    {
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{ "access_token": "token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh_token", "scope": "sso" }'),
            new Response(200, ['Content-Type' => 'application/json'], '{ "access_token": "token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh_token", "scope": "sso" }')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->assertIsArray($this->oc->refreshToken("mytoken"));
        $this->assertEquals('{"access_token":"token","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh_token","scope":"sso"}',json_encode($this->oc->refreshToken("mytoken")));
    }

    public function testVerifyError(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/Too few arguments/");
        $this->oc->verify();
    }

    public function testVerifyException(): void 
    {
        // $this->expectException(RequestException::class);
        $this->expectError();
        $this->expectErrorMessageMatches("/Unauthorized/");
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(401)
            // new RequestException('Error Communicating with Server', new Request('GET', API_ENDPOINT.'/oauth/verify'))
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => true,
			'verify' => false
        ]);

        $this->oc->setClient($client);
        $this->oc->verify("mytoken");
    }

    public function testVerifyStatusError(): void 
    {
        $this->expectError();
        $this->expectErrorMessageMatches("/Undefined Error/");
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"code": 200, "status": false, "error": "Undefined Error"}')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->oc->verify("mytoken");
    }

    public function testVerifyFalse(): void 
    {
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(400, ['Content-Type' => 'application/json'], 'Bad Request')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->assertFalse($this->oc->verify("mytoken"));
    }

    public function testVerify(): void 
    {
        // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"code": 200, "status": true}')
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client([
            'handler' => $handlerStack,
            'base_uri' => API_ENDPOINT,
			'timeout'  => 2.0,
            'http_errors' => false,
			'verify' => true
        ]);

        $this->oc->setClient($client);
        $this->assertTrue($this->oc->verify("mytoken"));
    }
}
