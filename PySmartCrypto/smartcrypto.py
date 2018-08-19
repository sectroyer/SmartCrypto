from __future__ import print_function
import crypto
import sys
import re
import requests

UserId = "654321"
AppId = "12345"
deviceId =  "7e509404-9d7c-46b4-8f6a-e2a9668ad184"
tvIP = "192.168.0.21"
tvPort = "8080"
lastRequestId = 0
def getFullUrl(urlPath):
    global tvIP, tvPort
    return "http://"+tvIP+":"+tvPort+urlPath

def GetFullRequestUri(step, appId, deviceId):
    return getFullUrl("/ws/pairing?step="+str(step)+"&app_id="+appId+"&device_id="+deviceId)

def ShowPinPageOnTv():
    requests.post(getFullUrl("/ws/apps/CloudPINPage"), "pin4")

def CheckPinPageOnTv():
    full_url = getFullUrl("/ws/apps/CloudPINPage")
    page = requests.get(full_url).text
    output = re.search('state>([^<>]*)</state>', page, flags=re.IGNORECASE)
    if output is not None:
        state = output.group(1)
        print("Current state: "+state)
        if state == "stopped":
            return True
    return False

def FirstStepOfPairing():
    global AppId, deviceId;
    firstStepURL = GetFullRequestUri(0,AppId, deviceId)+"&type=1"
    firstStepResponse = requests.get(firstStepURL).text

def StartPairing():
    global lastRequestId
    lastRequestId=0
    if CheckPinPageOnTv():
        print("Pin NOT on TV")
        ShowPinPageOnTv()
    else:
        print("Pin ON TV");
def HelloExchange(pin):
    global AppId, deviceId, lastRequestId, UserId
    hello_output = crypto.generateServerHello(UserId,pin)
    if not hello_output:
        return False
    content = "{\"auth_Data\":{\"auth_type\":\"SPC\",\"GeneratorServerHello\":\"" + hello_output['serverHello'].encode('hex').upper() + "\"}}"
    secondStepURL = GetFullRequestUri(1, AppId, deviceId)
    secondStepResponse = requests.post(secondStepURL, content).text
    print('secondStepResponse: ' + secondStepResponse)
    output = re.search('request_id.*?(\d).*?GeneratorClientHello.*?:.*?(\d[0-9a-zA-Z]*)', secondStepResponse, flags=re.IGNORECASE)
    if output is None:
        return False
    requestId = output.group(1)
    clientHello = output.group(2)
    lastRequestId = int(requestId)
    return crypto.parseClientHello(clientHello, hello_output['hash'], hello_output['AES_key'], UserId)

def AcknowledgeExchange(SKPrime):
    global lastRequestId, AppId,  deviceId;
    serverAckMessage = crypto.generateServerAcknowledge(SKPrime)
    content="{\"auth_Data\":{\"auth_type\":\"SPC\",\"request_id\":\"" + str(lastRequestId) + "\",\"ServerAckMsg\":\"" + serverAckMessage + "\"}}"
    thirdStepURL = GetFullRequestUri(2, AppId, deviceId)
    thirdStepResponse = requests.post(thirdStepURL, content).text
    if "secure-mode" in thirdStepResponse:
        print("TODO: Implement handling of encryption flag!!!!")
        sys.exit(-1)
    output = re.search('ClientAckMsg.*?:.*?(\d[0-9a-zA-Z]*).*?session_id.*?(\d)', thirdStepResponse, flags=re.IGNORECASE)
    if output is None:
        print("Unable to get session_id and/or ClientAckMsg!!!");
        sys.exit(-1)
    clientAck = output.group(1)
    if not crypto.parseClientAcknowledge(clientAck, SKPrime):
        print("Parse client ac message failed.")
        sys.exit(-1)
    sessionId=output.group(2)
    print("sessionId: "+sessionId)
    return sessionId
def ClosePinPageOnTv():
    full_url = getFullUrl("/ws/apps/CloudPINPage/run");
    requests.delete(full_url)
    return False

StartPairing()
ctx = False
SKPrime = False
while not ctx:
    tvPIN = raw_input("Please enter pin from tv: ")
    print("Got pin: '"+tvPIN+"'\n")
    FirstStepOfPairing()
    output = HelloExchange(tvPIN)
    if output:
        ctx = output['ctx']
        SKPrime = output['SKPrime']
        print("ctx: " + ctx.encode('hex'))
        print("Pin accepted :)\n")
    else:
        print("Pin incorrect. Please try again...\n")

currentSessionId = AcknowledgeExchange(SKPrime)
ClosePinPageOnTv()
print("Authorization successfull :)\n")

