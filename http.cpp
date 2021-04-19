#include "http.h"

HTTPRequest *HTTPRequest::parse(const char *msg)
{
    const std::regex req("(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) (\\S+) (HTTP/\\d\\.\\d)\r\n");
    const std::regex host("Host: (\\S+)\r\n");

    std::cmatch mat;

    if (std::regex_search(msg, mat, req)) {
        HTTPRequest *r = new HTTPRequest;
        r->method = std::string(mat[1]);
        r->uri = std::string(mat[2]);
        r->version = std::string(mat[3]);

        if (std::regex_search(msg, mat, host)) {
            r->host = std::string(mat[1]);
        }

        return r;
    }

    return nullptr;
}

HTTPResponse *HTTPResponse::parse(const char *msg)
{
    const std::regex resp("(HTTP/\\d\\.\\d) (\\d+) (.+)\r\n");

    std::cmatch mat;

    if (std::regex_search(msg, mat, resp)) {
        HTTPResponse *r = new HTTPResponse;
        r->version = std::string(mat[1]);
        r->code = std::string(mat[2]);
        r->message = std::string(mat[3]);

        return r;
    }

    return nullptr;
}
