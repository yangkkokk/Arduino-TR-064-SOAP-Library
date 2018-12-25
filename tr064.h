#ifndef TR064_H
#define TR064_H

#include <map>
#include <vector>
//#include "...." // for your types and classes

// The type 'String' I don't know

// type for list of supported services as replacement 
// for 'String _services[100][2]', 
// because the original code is ANSI-C not C++
// - first element = key = value of <serviceType>
// - second element = value = value of <controlURL>
using ServiceMap = std::map<String, String>;    

// This type to replace 'String' field for argument 'params' in methods 'action'
struct ParamType {
    String  name;   // replacement for String[0]
    String  value;  // replacement for String[1]
};

// List of parameters. Counters can be omitted in Methods 'action'.
using ParamList = std::vector<ParamType>;

class TR064
{
  public:
    // 'const' is your friend for safer code
    TR064(const int port, const String ip, 
          const String user, const String pass);
    void init();

    String action(const String service, const String act);
    String action(const String service, const String act, 
                  const ParamList params);
    String action(const String service, const String act, 
                  const ParamList params, ParamList& result);
    bool xmlTakeParam(const String inStr, const String needParam, 
                      String& result, bool sensitive = true);

    String md5String(const String text);
    
  private:
    void initServiceURLs();
    void initNonce();
    String httpRequest(const String url, const String xml, const String action);
    String generateAuthToken();
    String generateAuthXML();
    bool findServiceURL(const String service, String& result);  
    
    const String _ip;   // 'const' added
    const int _port;    // 'const' added
    const String _user; // 'const' added
    const String _pass; // 'const' added
    String _realm; //To be requested from the router
    String _secretH; //to be generated
    String _nonce = "";
    const String _requestStart = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">";
    const String _detectPage = "/tr64desc.xml";
    ServiceMap _services; // replaced with mapping list
    bool _error = false;
};
