<?php
namespace Payment\Notify;

use Payment\Common\AliConfig;
use Payment\Common\PayException;
use Payment\Config;
use Payment\Utils\ArrayUtil;
use Payment\Utils\Rsa2Encrypt;
use Payment\Utils\RsaEncrypt;

/**
 * 阿里同步回调通知
 * Class AliSyncNotify
 * @package Payment\Notify
 */
class AliSyncNotify extends NotifyStrategy
{
    /**
     * AliNotify constructor.
     * @param array $config
     * @throws PayException
     */
    public function __construct(array $config)
    {
        try {
            $this->config = new AliConfig($config);
        } catch (PayException $e) {
            throw $e;
        }
    }

    /**
     * 获取移除通知的数据  并进行简单处理（如：格式化为数组）
     *
     * 如果获取数据失败，返回false
     *
     * @return array|boolean
     * @author helei
     */
    public function getNotifyData()
    {

        $data = empty($_POST) ? $_GET : $_POST;
        if (empty($data) || ! is_array($data)) {
            return false;
        }

        return $data;
    }

    /**
     * 检查异步通知的数据是否合法
     *
     * 如果检查失败，返回false
     *
     * @param array $data  由 $this->getNotifyData() 返回的数据
     * @return boolean
     * @author helei
     */
    public function checkNotifyData(array $data)
    {
        // 检查签名
        return $this->verifySign($data);
    }

    /**
     * 向客户端返回必要的数据
     * @param array $data 回调机构返回的回调通知数据
     * @return array|false
     * @author helei
     */
    protected function getRetData(array $data)
    {
        if ($this->config->returnRaw) {
            $data['channel'] = Config::ALI_CHARGE;
            return $data;
        }

        $retData = [
            'charset'   => ArrayUtil::get($data, 'charset'),
            'method' => ArrayUtil::get($data, 'method'),
            'app_id' => ArrayUtil::get($data, 'app_id'),
            'transaction_id'   => ArrayUtil::get($data, 'trade_no'),
            'order_no'   => ArrayUtil::get($data, 'out_trade_no'),
            'seller_id' => ArrayUtil::get($data, 'seller_id'),
            'trade_state'   => $this->getTradeStatus($data['trade_status']),
            'amount'   => ArrayUtil::get($data, 'total_amount'),
            'channel'   => Config::ALI_CHARGE,
        ];

        // 检查是否存在用户自定义参数
        if (isset($data['passback_params']) && ! empty($data['passback_params'])) {
            $retData['return_param'] = $data['passback_params'];
        }
        // 支付成功的各个渠道金额信息
        if (isset($data['fund_bill_list']) && ! empty($data['fund_bill_list'])) {
            $retData['fund_bill_list'] = \GuzzleHttp\json_decode($data['fund_bill_list'], true);
        }
        // 优惠券信息
        if (isset($data['voucher_detail_list']) && ! empty($data['voucher_detail_list'])) {
            $retData['voucher_detail_list'] = \GuzzleHttp\json_decode($data['voucher_detail_list'], true);
        }

        return $retData;
    }

    /**
     * 支付宝，成功返回 ‘success’   失败，返回 ‘fail’
     * @param boolean $flag 每次返回的bool值
     * @param string $msg 错误原因  后期考虑记录日志
     * @return string
     * @author helei
     */
    protected function replyNotify($flag, $msg = '')
    {
        if ($flag) {
            return 'success';
        } else {
            return 'fail';
        }
    }

    /**
     * 返回统一的交易状态
     * @param $status
     * @return string
     * @author helei
     */
    protected function getTradeStatus($status)
    {
        if (in_array($status, ['TRADE_SUCCESS', 'TRADE_FINISHED'])) {
            return Config::TRADE_STATUS_SUCC;
        } else {
            return Config::TRADE_STATUS_FAILD;
        }
    }

    /**
     * 检查支付宝数据 签名是否被篡改
     * @param array $data
     * @return boolean
     * @author helei
     */
    protected function verifySign(array $data)
    {
        $signType = strtoupper($data['sign_type']);
        $sign = $data['sign'];

        // 1. 剔除sign与sign_type参数
        $values = ArrayUtil::removeKeys($data, ['sign', 'sign_type']);
        //  2. 移除数组中的空值
        $values = ArrayUtil::paraFilter($values);
        // 3. 对待签名参数数组排序
        $values = ArrayUtil::arraySort($values);
        // 4. 将排序后的参数与其对应值，组合成“参数=参数值”的格式,用&字符连接起来
        $preStr = ArrayUtil::createLinkstring($values);

        if ($signType === 'RSA') {// 使用rsa方式
            $rsa = new RsaEncrypt($this->config->rsaAliPubKey);

            return $rsa->rsaVerify($preStr, $sign);
        } elseif ($signType === 'RSA2') {
            $rsa = new Rsa2Encrypt($this->config->rsaAliPubKey);

            return $rsa->rsaVerify($preStr, $sign);
        } else {
            return false;
        }
    }
}
