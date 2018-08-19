#!/usr/bin/php
<?
require('tv_geturl.php');

$UserId = "654321";
$AppId = "12345";
$dest_hash = "";
$SKPrime = "";
$ctx = "";
//$Guid =  "7e509404-9d7c-46b4-8f6a-e2a9668ad184";
$deviceId =  "7e509404-9d7c-46b4-8f6a-e2a9668ad184";
$hash = "";
$AES_key= "";
$lastRequestId = "";
$sessionId = 0;
$tvIP = "192.168.0.21";
$tvPort = "8080";

function getFullUrl($urlPath)
{
	global $tvIP, $tvPort;
	return "http://".$tvIP.":".$tvPort.$urlPath;
}
function GetFullRequestUri($step, $appId, $deviceId)
{
	return getFullUrl("/ws/pairing?step=".$step."&app_id=".$appId."&device_id=".$deviceId);
}
function CheckPinPageOnTv()
{
	$full_url = getFullUrl("/ws/apps/CloudPINPage");
	$page = geturl($full_url,$tvPort);
	if(preg_match("@<state>([^<>]*)</state>@si",$page,$out))
	{
		echo "Current state: ".$out[1]."\n";
		if($out[1] == "stopped")
		{
			return true;
		}
	}
	return false;
}
function ShowPinPageOnTv()
{
	geturl2(getFullUrl("/ws/apps/CloudPINPage"), "pin4");
}
function StartPairing()
{
	global $lastRequestId;
	$lastRequestId=0;
	if(CheckPinPageOnTv())
	{
		echo "Pin NOT on TV"."\n";
		ShowPinPageOnTv();
	}
	else
		echo "Pin ON TV"."\n";
}
function FirstStepOfPairing()
{
	global $AppId, $deviceId;
	$firstStepURL = GetFullRequestUri(0,$AppId, $deviceId)."&type=1";
	//echo("firstStepURL: '".$firstStepURL."'\n");
	$firstStepResponse = geturl($firstStepURL);
	//echo ("firstStepResponse: ".$firstStepResponse."");
}
function GenerateServerHello($pin)
{
	global $UserId ,$hash,$AES_key;
	$res = shell_exec("./smartcrypto generateServerHello $UserId $pin");
	if(preg_match("@AES key: ([^ \n]*).*hash: ([^ \n]*).*ServerHello: ([^ \n]*)@si",$res,$out))
	{
		$AES_key = $out[1];
		$hash = $out[2];
		return $out[3];
	}
	return false;
}
function parseClientHello($clientHello)
{
	global $UserId, $hash, $AES_key,$dest_hash, $SKPrime, $ctx;
	$res = shell_exec("./smartcrypto parseClientHello $clientHello $hash $AES_key $UserId");
	if(preg_match("@dest_hash: ([^ \n]*).*SKPrime: ([^ \n]*).*ctx: ([^ \n]*)@si",$res,$out))
	{
		$dest_hash = $out[1];
		$SKPrime = $out[2];
		$ctx = $out[3];
		echo "dest_hash: $dest_hash\n";
		echo "SKPrime: $SKPrime\n";
		echo "ctx: $ctx\n";
		return true;
	}
	return false;
}
function HelloExchange($pin)
{
	global $AppId, $deviceId, $lastRequestId, $hash, $AES_key;
	$serverHello = GenerateServerHello($pin);
	if(!$serverHello)
		return false;
	$content = "{\"auth_Data\":{\"auth_type\":\"SPC\",\"GeneratorServerHello\":\"".$serverHello."\"}}";
	$secondStepURL = GetFullRequestUri(1,$AppId, $deviceId);
	//echo "secondStepURL: '".$secondStepURL."'\n";
	//echo "secondStep content: '".$content."'\n";
	$secondStepResponse = geturl2($secondStepURL,$content);
	//echo "secondStepResponse: ".$secondStepResponse."";
	if(!preg_match("@request_id.*?(\d).*?GeneratorClientHello.*?:.*?(\d[0-9a-zA-Z]*)@si",$secondStepResponse,$out))
		return false;
	#var_dump($out);
	$requestId = $out[1];
	$clientHello = $out[2];
	//echo "clientHello: '".$clientHello."'\n";
	//echo "requestId: '".$requestId."'\n";
	//echo "hash: '".$hash."'\n";
	//echo "AES key: '".$AES_key."'\n";
	$lastRequestId = $requestId; 
	return parseClientHello($clientHello);
}
function generateServerAcknowledge()
{
	global $SKPrime;
	$SKPrimeHash = sha1(hex2bin($SKPrime."01"));
	return "0103000000000000000014".strtoupper($SKPrimeHash)."0000000000";
}
function ParseClientAcknowledge($clientAck)
{
	global $SKPrime;
	$SKPrimeHash = sha1(hex2bin($SKPrime."02"));
	$tmpClientAck = "0104000000000000000014".strtoupper($SKPrimeHash)."0000000000";
	return $clientAck === $tmpClientAck;
}
function AcknowledgeExchange()
{
	global $lastRequestId,$AppId, $deviceId, $sessionId;
	$serverAckMessage = generateServerAcknowledge();
	$content="{\"auth_Data\":{\"auth_type\":\"SPC\",\"request_id\":\"".$lastRequestId."\",\"ServerAckMsg\":\"".$serverAckMessage."\"}}";
	$thirdStepURL = GetFullRequestUri(2,$AppId, $deviceId);
	//echo "thirdStepURL: '".$thirdStepURL."'\n";
	//echo "thirdStep content: $content\n";
	$thirdStepResponse = geturl2($thirdStepURL,$content);
	//echo "thirdStepResponse: '$thirdStepResponse'";
    if(strstr($thirdStepResponse,"secure-mode"))
	{
    	echo "TODO: Implement handling of encryption flag!!!!\n";
		die(-1);
	}
	if(!preg_match("@ClientAckMsg.*?:.*?(\d[0-9a-zA-Z]*).*?session_id.*?(\d)@si",$thirdStepResponse,$out))
	{
		echo "Unable to get session_id and/or ClientAckMsg!!!\n";
		die(-1);
	}
	$clientAck = $out[1];
	//echo "clientAck: '$clientAck'\n";
	if(!ParseClientAcknowledge($clientAck))
	{
		echo "Parse client ac message failed.\n";
		die(-1);
	}
	$sessionId=$out[2];
	echo "sessionId: $sessionId\n";
	return $sessionId;
}
function ClosePinPageOnTv()
{
	geturl(getFullUrl("/ws/apps/CloudPINPage/run"),"DELETE");
   return false;
}
StartPairing();
$pinAccepted = false;
do 
{
	echo "Please enter pin from tv:\n";
	$tvPIN = readline();
	echo "Got pin: '".$tvPIN."'\n";
	FirstStepOfPairing();
	$pinAccepted=HelloExchange($tvPIN);
	if($pinAccepted)
		echo "Pin accepted :)\n\n";
	else
		echo "Pin incorrect. Please try again...\n\n";
}while(!$pinAccepted);
$currentSessionId = AcknowledgeExchange();
ClosePinPageOnTv();
echo "Authorization successfull :)\n\n";
?>
