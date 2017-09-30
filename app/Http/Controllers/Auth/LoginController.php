<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use League\OAuth2\Client\Provider\GenericProvider;
use Symfony\Component\HttpKernel\Client;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login(Request $request)
    {
        $provider = new GenericProvider([
            'clientId' => 'htAZFp7DCwnd1A9q4yDwbyWX',
            'clientSecret' => '9EADF115A76B760B16089708D06D6BF2EC08CE2C5E613D9B',
            'redirectUri' => 'http://127.0.0.1:8000/user/login',
            'urlAuthorize' => 'https://jaccount.sjtu.edu.cn/oauth2/authorize',
            'urlAccessToken' => 'https://jaccount.sjtu.edu.cn/oauth2/token',
            'urlResourceOwnerDetails' => 'https://api.sjtu.edu.cn/v1/me/profile'
        ]);

        if (!$request->input('code')) {
            header('Location: ' . $provider->getAuthorizationUrl());
            exit;
        } else {
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $request->input('code')
            ]);
            echo 'Access Token: ' . $accessToken->getToken() . "<br>";
            echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
            echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
            echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";

//            $resourceOwner = $provider->getResourceOwner($accessToken);
            //var_export($resourceOwner->toArray());

//            print_r($request);

            $request = $provider->getAuthenticatedRequest(
                'GET',
                'https://api.sjtu.edu.cn/v1/me/profile',
                $accessToken
            );

            $client = new \GuzzleHttp\Client();
            $response = $client->send($request);
            $result = json_decode($response->getBody());
            print_r($result);



//            print_r($request);

        }

    }
}
