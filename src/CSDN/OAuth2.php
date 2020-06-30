<?php


namespace CoverCMS\Socialite\CSDN;


use CoverCMS\Socialite\AbstractOAuth2;
use CoverCMS\Socialite\Exception;
use GuzzleHttp\Exception\ClientException;

class OAuth2 extends AbstractOAuth2
{
    /**
     * api域名
     */
    const API_DOMAIN = 'http://api.csdn.net/';

    /**
     * 获取url地址
     * @param string $name 跟在域名后的文本
     * @param array $params GET参数
     * @return string
     */
    public function getUrl($name, $params = array())
    {
        return static::API_DOMAIN . $name . (empty($params) ? '' : ('?' . $this->http_build_query($params)));
    }

    /**
     * 使用账号密码方式登录授权
     * @param string $username 用户名
     * @param string $password 密码
     * @return void
     */
    public function login($username, $password)
    {
        try {
            $response = $this->http->get($this->getUrl('oauth2/access_token'), array(
                'grant_type' => 'password ',
                'username' => $username,
                'password' => $password,
                'client_id' => $this->appid,
                'client_secret' => $this->appSecret,
            ));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (!isset($this->result['error_code'])) {
            return $this->accessToken = $this->result['access_token'];
        } else {
            throw new Exception(isset($this->result['error']) ? $this->result['error'] : '', $this->result['error_code']);
        }
    }

    /**
     * 第一步:获取登录页面跳转url
     * @param string $callbackUrl 登录回调地址
     * @param string $state 无用
     * @param array $scope 无用
     * @return string
     */
    public function getAuthUrl($callbackUrl = null, $state = null, $scope = null)
    {
        $option = array(
            'client_id' => $this->appid,
            'redirect_uri' => null === $callbackUrl ? $this->callbackUrl : $callbackUrl,
            'response_type' => 'code',
        );
        if (null === $this->loginAgentUrl) {
            return $this->getUrl('oauth2/authorize', $option);
        } else {
            return $this->loginAgentUrl . '?' . $this->http_build_query($option);
        }
    }

    /**
     * 第二步:处理回调并获取access_token。与getAccessToken不同的是会验证state值是否匹配，防止csrf攻击。
     * @param string $storeState 存储的正确的state
     * @param string $code 第一步里$redirectUri地址中传过来的code，为null则通过get参数获取
     * @param string $state 回调接收到的state，为null则通过get参数获取
     * @return string
     */
    protected function __getAccessToken($storeState, $code = null, $state = null)
    {
        try {
            $response = $this->http->get($this->getUrl('oauth2/access_token'), array(
                'grant_type' => 'authorization_code',
                'code' => isset($code) ? $code : (isset($_GET['code']) ? $_GET['code'] : ''),
                'client_id' => $this->appid,
                'client_secret' => $this->appSecret,
                'redirect_uri' => $this->getRedirectUri(),
            ));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (!isset($this->result['error_code'])) {
            return $this->accessToken = $this->result['access_token'];
        } else {
            throw new Exception(isset($this->result['error']) ? $this->result['error'] : '', $this->result['error_code']);
        }
    }

    /**
     * 获取用户资料
     * @param string $accessToken
     * @return array
     */
    public function getUserInfo($accessToken = null)
    {
        try {
            $response = $this->http->get($this->getUrl('user/getinfo', array(
                'access_token' => null === $accessToken ? $this->accessToken : $accessToken,
            )));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (!isset($this->result['error_code'])) {
            $this->openid = $this->result['username'];
            return $this->result;
        } else {
            throw new Exception(isset($this->result['error']) ? $this->result['error'] : '', $this->result['error_code']);
        }
    }

    /**
     * 刷新AccessToken续期
     * @param string $refreshToken
     * @return bool
     */
    public function refreshToken($refreshToken)
    {
        // 不支持
        return false;
    }

    /**
     * 检验授权凭证AccessToken是否有效
     * @param string $accessToken
     * @return bool
     */
    public function validateAccessToken($accessToken = null)
    {
        try {
            $this->getUserInfo($accessToken);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
}