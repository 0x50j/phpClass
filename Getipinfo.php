<?php

/**
 * 获取 ip 地址信息类
 */
class Getipinfo
{
	//获取 ip 地址信息的方法函数
	function getipinfo(argument)
	{
		//调用淘宝的IP地址库获取对应信息
		$client_ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
		$url='http://ip.taobao.com/service/getIpInfo.php?ip='.$client_ip;

		$curl = curl_init();
		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_FAILONERROR, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_HEADER, false);
		$ip_info = json_decode(curl_exec($curl),TRUE);

		//获得IP地址对应所在的国家
		$ip_country=$ip_info['data']['country'];
		//获得IP地址对应所在的国家地区
		$ip_region=$ip_info['data']['region'];
		//获得IP地址对应所在的国家城市
		$ip_region=$ip_info['data']['city'];
		//获得IP地址对应所在的国家地区编号
		$ip_region=$ip_info['data']['region_id'];
		//获得IP地址对应所在的国家城市编号
		$ip_region=$ip_info['data']['city_id'];
	}
}

?>