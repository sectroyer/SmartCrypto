<?php
$gurl;
$ghttps;
date_default_timezone_set('Europe/Warsaw');
function geturl($url,$method="GET")
{
	global $gurl;
	$gurl=$url;
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
	//curl_setopt($curl, CURLOPT_VERBOSE, 1);
	//curl_setopt($curl, CURLOPT_HEADER, true);
	curl_setopt($curl, CURLOPT_FOLLOWLOCATION,1);
	curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,false);
	curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
	curl_setopt($curl,CURLOPT_COOKIEFILE,realpath("cookie.txt"));
	curl_setopt($curl,CURLOPT_COOKIEJAR,realpath("cookie.txt"));
	curl_setopt($curl,CURLOPT_PROXY,"");
	curl_setopt($curl,CURLOPT_TIMEOUT, 60);
	curl_setopt ($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)");
	$ret = curl_exec($curl);
	curl_close($curl);
	return $ret;
}
function geturl2($url,$post)
{
	global $gurl;
	$gurl=$url;
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_PORT, $port);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curl, CURLOPT_FOLLOWLOCATION,1);
	curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,false);
	curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
	curl_setopt($curl,CURLOPT_COOKIEFILE,"./cookie.txt");
	curl_setopt($curl,CURLOPT_COOKIEJAR,"./cookie.txt");
	curl_setopt($curl,CURLOPT_HTTPHEADER,array("Expect:","Content-Type: application/x-www-form-urlencoded"));
	curl_setopt($curl,CURLOPT_POST,1);
	curl_setopt($curl,CURLOPT_POSTFIELDS,$post);
	#curl_setopt($curl,CURLOPT_REFERER,".com.pl/frames.aspx");
	curl_setopt($curl,CURLOPT_PROXY,"");
	curl_setopt($curl,CURLOPT_TIMEOUT, 60);
	curl_setopt ($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)");
	$ret = curl_exec($curl);
	curl_close($curl);
	return $ret;
}
