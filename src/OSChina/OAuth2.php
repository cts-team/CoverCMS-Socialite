<?php


namespace CoverCMS\Socialite\OSChina;


use CoverCMS\Socialite\AbstractOAuth2;
use CoverCMS\Socialite\Exception;
use GuzzleHttp\Exception\ClientException;

class OAuth2 extends AbstractOAuth2
{
    /**
     * api域名
     */
    const API_DOMAIN = 'https://www.oschina.net/';

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
     * 第一步:获取登录页面跳转url
     * @param string $callbackUrl 登录回调地址
     * @param string $state 状态值，不传则自动生成，随后可以通过->state获取。用于第三方应用防止CSRF攻击，成功授权后回调时会原样带回。一般为每个用户登录时随机生成state存在session中，登录回调中判断state是否和session中相同
     * @param array $scope 无用
     * @return string
     */
    public function getAuthUrl($callbackUrl = null, $state = null, $scope = null)
    {
        $option = array(
            'client_id' => $this->appid,
            'response_type' => 'code',
            'redirect_uri' => null === $callbackUrl ? $this->callbackUrl : $callbackUrl,
            'state' => $this->getState($state),
        );
        if (null === $this->loginAgentUrl) {
            return $this->getUrl('action/oauth2/authorize', $option);
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
            $response = $this->http->get($this->getUrl('action/openapi/token'), array(
                'client_id' => $this->appid,
                'client_secret' => $this->appSecret,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->getRedirectUri(),
                'code' => isset($code) ? $code : (isset($_GET['code']) ? $_GET['code'] : ''),
                'dataType' => 'json',
            ));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (!isset($this->result['error'])) {
            return $this->accessToken = $this->result['access_token'];
        } else {
            throw new Exception(isset($this->result['error_description']) ? $this->result['error_description'] : '', $response->getStatusCode());
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
            $response = $this->http->get($this->getUrl('action/openapi/user', array(
                'access_token' => null === $accessToken ? $this->accessToken : $accessToken,
                'dataType' => 'json',
            )));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (isset($this->result['id'])) {
            $this->openid = $this->result['id'];
            return $this->result;
        } else {
            throw new Exception(isset($this->result['error_description']) ? $this->result['error_description'] : '', $response->getStatusCode());
        }
    }

    /**
     * 刷新AccessToken续期
     * @param string $refreshToken
     * @return bool
     */
    public function refreshToken($refreshToken)
    {
        try {
            $response = $this->http->get($this->getUrl('action/openapi/token'), array(
                'client_id' => $this->appid,
                'client_secret' => $this->appSecret,
                'grant_type' => 'refresh_token',
                'redirect_uri' => $this->getRedirectUri(),
                'refresh_token' => $refreshToken,
                'dataType' => 'json',
            ));
        } catch (ClientException $exception) {
            $response = $exception->getResponse();
        }
        $this->result = json_decode($response->getBody()->getContents(), true);

        if (!isset($this->result['error'])) {
            return $this->accessToken = $this->result['access_token'];
        } else {
            throw new Exception(isset($this->result['error_description']) ? $this->result['error_description'] : '', $response->getStatusCode());
        }
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