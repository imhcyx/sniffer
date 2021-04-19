#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <regex>

class HTTPRequest
{
public:
    static HTTPRequest *parse(const char *msg);

    std::string getMethod() { return method; }
    std::string getURI() { return uri; }
    std::string getVersion() { return version; }
    std::string getHost() { return host; }

private:
    std::string method, uri, version, host;

    HTTPRequest() {}
};

class HTTPResponse
{
public:
    static HTTPResponse *parse(const char *msg);

    std::string getVersion() { return version; }
    std::string getCode() { return code; }
    std::string getMessage() { return message; }

private:
    std::string version, code, message;

    HTTPResponse() {}
};

#endif // HTTP_H
