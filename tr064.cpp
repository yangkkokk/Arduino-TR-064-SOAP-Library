/*
  tr064.h - Library for communicating via TR-064 protocol
  (e.g. Fritz!Box)
  A descriptor of the protocol can be found here: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_TR-064_first_steps.pdf
  The latest Version of this library can be found here: http://github.com/Aypac
  Created by René Vollmer, November 2016
  
  Better C++ code by Raymond Czerny, December 2018
*/

// basic integer types
#include <cstdint>

// for byte to String (hex) converting
#include <sstream>
#include <iomanip>

// use logic names: not, or, xor ... 
#include <ciso646> 

#include "_tr064.hpp"

TR064::TR064(const int port, const String ip, 
             const String user, const String pass)
  : _port(port)
  , _ip(ip)
  , _user(user)
  , _pass(pass)
{
}

// Fetches a list of all services and the associated urls
void TR064::initServiceURLs() {
   constexpr size_t COUNT_CHAR = std::string("service").size(); //length of word "service"
   const String inStr = httpRequest(_detectPage, "", "");
   // int i = 0; disabled, because needless
   while (inStr.indexOf("<service>") > 0 or inStr.indexOf("</service>") > 0) {
       const int indexStart = inStr.indexOf("<service>");
       const int indexStop  = inStr.indexOf("</service>");
       const String serviceXML  = inStr.substring(indexStart + COUNT_CHAR + 2, indexStop);
       const String servicename = xmlTakeParam(serviceXML, "serviceType");
       const String controlurl  = xmlTakeParam(serviceXML, "controlURL");
#if 0 // original code disabled   
       _services[i][0] = servicename;
       _services[i][1] = controlurl;
       ++i;
#else // new C++ code
       _services[servicename] = controlurl; // save as key-value pair
#endif
       if(Serial) {
           Serial.printf("Service no %d:\t", /* i replaced */ _service.size());
           Serial.flush();
           Serial.println(servicename + " @ " + controlurl);
       }
       inStr = inStr.substring(indexStop + COUNT_CHAR + 3);
   }
}

// Fetches the initial nonce and the realm
void TR064::initNonce() {
    if(Serial) Serial.print("Geting the initial nonce and realm\n");
    ParamList a;
    a.push_back({"NewAssociatedDeviceIndex", "1"});
    action("urn:dslforum-org:service:WLANConfiguration:1", "GetGenericAssociatedDeviceInfo", a);
    if(Serial) Serial.print("Got the initial nonce: " + _nonce + " and the realm: " + _realm + "\n");
}

//Returns the xml-header for authentification
String TR064::generateAuthXML() {
    String token;
    if (_nonce == "" or _error) { //If we do not have a nonce yet, we need to use a different header
       token="<s:Header><h:InitChallenge xmlns:h=\"http://soap-authentication.org/digest/2001/10/\" s:mustUnderstand=\"1\"><UserID>"+_user+"</UserID></h:InitChallenge ></s:Header>";
    } else { //Otherwise we produce an authorisation header
      token = generateAuthToken();
      token = "<s:Header><h:ClientAuth xmlns:h=\"http://soap-authentication.org/digest/2001/10/\" s:mustUnderstand=\"1\"><Nonce>" + _nonce + "</Nonce><Auth>" + token + "</Auth><UserID>"+_user+"</UserID><Realm>"+_realm+"</Realm></h:ClientAuth></s:Header>";
    }
    return token;
}

// Returns the authentification token based on the hashed secret and the last nonce.
String TR064::generateAuthToken() {
    String token = md5String(_secretH + ":" + _nonce);
    if(Serial) Serial.print("The auth token is " + token + "\n");
    return token;
}


// This function will call an action on the service.
String TR064::action(const String service, const String act) {
    if(Serial) Serial.println("action_2");
    ParamList p;    // empty list
    return action(service, act, p);
}

// This function will call an action on the service.
// With params you set the arguments for the action
// e.g. String params[][2] = {{ "arg1", "value1" }, { "arg2", "value2" }};
String TR064::action(const String service, const String act, const ParamList params) {
    if(Serial) Serial.println("action_1");

	// Generate the xml-envelop
    String xml = _requestStart + generateAuthXML() + "<s:Body><u:"+act+" xmlns:u='" + service + "'>";
	// add request-parameters to xml
    
#if 0   // old code
    if (nParam > 0) {
        for (int i=0;i<nParam;++i) {
	    if (params[i][0] != "") {
                xml += "<"+params[i][0]+">"+params[i][1]+"</"+params[i][0]+">";
            }
        }
    }
#else // new C++ code
    for(const ParamType& p : params)
    {
        if("" != p.name)
        {
            xml += "<" + p.name + ">"+ p.value +"</" + p.name + ">";
        }
    }
#endif
	// close the envelop
    xml += "</u:" + act + "></s:Body></s:Envelope>";
	// The SOAPACTION-header is in the format service#action
    String soapaction = service+"#"+act;

	// Send the http-Request
    String url;
    if(not findServiceURL(service, url))
    {
        // TODO: Error managment
    }
    String xmlR = httpRequest(url, xml, soapaction);

	// Extract the Nonce for the next action/authToken.
    if (xmlR != "") {
        bool success xmlTakeParam(xmlR, "Nonce", _nonce);
        if("" == _realm)
        {
            success = success and xmlTakeParam(xmlR, "Realm", _realm);
        }
        if(not success)
        {
            // TODO: Error managment
        }
    }
    return xmlR;
}


// This function will call an action on the service.
// With params you set the arguments for the action
// e.g. String params[][2] = {{ "arg1", "value1" }, { "arg2", "value2" }};
// Will also fill the array req with the values of the assiciated return variables of the request.
// e.g. String req[][2] = {{ "resp1", "" }, { "resp2", "" }};
// will be turned into req[][2] = {{ "resp1", "value1" }, { "resp2", "value2" }};
String TR064::action(const String service, const String act, const ParamList params, ParamList& result) {
    if(Serial) Serial.println("action_3");
    String xmlR = action(service, act, params);
    String body;
    if(not xmlTakeParam(xmlR, "s:Body", body))
    {
        // TODO: Error managment
    }

    for(ParamType& p : result)
    {
        if("" != p.name)
        {
            String value;
            if(not xmlTakeParam(body, p.name, value))
            {
                // TODO: Error managment
            }
            p.value = value;
        }
    }
    return xmlR;
}

// Returns the (relative) url for a service
// The second argument is a C++ reference, similar to a pointer that must never be NULL.
bool TR064::findServiceURL(const String service, String& result) {
    ServiceMap::const_iterator it = _services.find(service);
    if(it != _services.end())
    {   // found
        result = it->second;
        return true;
    }
    //Service not found error!
    result = "";
    return false; // TODO: Proper error-handling?
}


// Puts a http-Request to the given url (relative to _ip on _port)
// - if specified POSTs xml and adds soapaction as header field.
// - otherwise just GETs the url
String TR064::httpRequest(const String url, const String xml, const String soapaction) {
    HTTPClient http;

    if(Serial) Serial.print("[HTTP] begin: "+_ip+":"+_port+url+"\n");
    
    http.begin(_ip, _port, url);
    if (soapaction != "") {
      http.addHeader("CONTENT-TYPE", "text/xml"); //; charset=\"utf-8\"
      http.addHeader("SOAPACTION", soapaction);
    }
    //http.setAuthorization(fuser.c_str(), fpass.c_str());


    // start connection and send HTTP header
    int httpCode=0;
    if (xml != "") {
      if(Serial) Serial.println("\n\n\n"+xml+"\n\n\n");
      httpCode = http.POST(xml);
      if(Serial) Serial.print("[HTTP] POST... SOAPACTION: "+soapaction+"\n");
    } else {
      httpCode = http.GET();
      if(Serial) Serial.print("[HTTP] GET...\n");
    }

    
    String payload = "";
    // httpCode will be negative on error
    if(httpCode > 0) {
        // HTTP header has been send and Server response header has been handled
        if(Serial) Serial.printf("[HTTP] POST... code: %d\n", httpCode);

        // file found at server
        if(httpCode == HTTP_CODE_OK) {
            payload = http.getString();
        }
    } else {
      // Error
	// TODO: Proper error-handling?
	_error=true;
	// This might not be the best place to do this, potentially endless loop!
	if (_error) {
		initNonce();
	}
      if(Serial) Serial.printf("[HTTP] POST... failed, error: %s\n", http.errorToString(httpCode).c_str());
      // TODO: _nonce="";
    }

    if(Serial) Serial.println("\n\n\n"+payload+"\n\n\n");
    http.end();
    return payload;
}

// ----------------------------
// ----- Helper-functions -----
// ----------------------------

String TR064::md5String(const String text){
  constexpr size_t BUFFER_SIZE = 16;    // magic numbers are evil  
  uint8_t bbuff[BUFFER_SIZE];  // uint8_t is more meaningful
  MD5Builder nonce_md5; 
  nonce_md5.begin();
  nonce_md5.add(text); 
  nonce_md5.calculate(); 
  nonce_md5.getBytes(bbuff);
  std::stringstream ss;
  ss << std::hex            // integer to hex
     << std::setw(2)        // two digits
     << std::setfill('0');  // fill higher digit, if require
  // for each loop, because C++ is clever
  for(uint8_t b : bbuff) 
  {
      ss << static_cast<unsigned int>(b); // casting require, because 8bit integer have a problem
  }
  String hash = ss.str().c_str(); // is const char*
  return hash;   
}

//Extract the content of an XML tag
//If you cannot find it case-sensitive, look case insensitive
// The third argument is a C++ reference, similar to a pointer that must never be NULL.
// The last argument is optional
bool TR064::xmlTakeParam(const String inStr, const String needParam, String& result, bool sensitive) {
  String need = needParam; 
  String str  = inStr;
  if(not sensitive)
  {
    need.toLowerCase();
    str.toLowerCase();
  }
  const int indexStart = str.indexOf("<" + need + ">");
  const int indexStop  = str.indexOf("</" + need + ">");  
  if (indexStart > 0 or indexStop > 0) {
     const int CountChar = needParam.length();
     result = inStr.substring(indexStart + CountChar + 2, indexStop);
     return true;
  }
  if(sensitive) // for no endless recursion
  {  // As backup
     // Calls itself, with switch for not case-sensitive
     return xmlTakeParam(inStr, needParam, result, false);
  }
  return false;
}
