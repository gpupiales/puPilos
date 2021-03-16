#
# This is an example VCL file for Varnish.
#
# It does not do anything by default, delegating control to the
# builtin VCL. The builtin VCL is called when there is no explicit
# return statement.
#
# See the VCL chapters in the Users Guide at https://www.varnish-cache.org/docs/
# and http://varnish-cache.org/trac/wiki/VCLExamples for more examples.

# Marker to tell the VCL compiler that this VCL has been adapted to the
# new 4.0 format.
vcl 4.0;

# Import libraries
import directors;
import std;

# Default backend definition. Set this to point to your content server.
backend default {
    .host = "backend-host";
    .port = "80";
    .first_byte_timeout = 300s;
}

acl purge {
  "localhost";
  "127.0.0.1";
}

sub vcl_recv {
    # Happens before we check if we have this in cache already.
    #
    # Typically you clean up the request here, removing cookies you don't need,
    # rewriting the request, etc.

    # unset req.http.Authorization;

    if (req.http.User-Agent ~ "iPhone" || req.http.User-Agent ~ "Android") {
        set req.http.X-UA-Device = "mobile";
    } else {
        set req.http.X-UA-Device = "desktop";
    }

    if (req.http.X-Forwarded-Proto ~ "(?i)https") {
        return (synth(601, "Redirect to https"));
    }

    # The admin pages go directly to backend
    if (req.url ~ "^/status\.php$" ||
        req.url ~ "^/update\.php" ||
        req.url ~ "^/install\.php" ||
        req.url ~ "^/apc\.php$" ||
        req.url ~ "^/admin" ||
        req.url ~ "^/admin/.*$" ||
        req.url ~ "^/user" ||
        req.url ~ "^/user/.*$" ||
        req.url ~ "^/users/.*$" ||
        req.url ~ "^/info/.*$" ||
        req.url ~ "^/flag/.*$" ||
        req.url ~ "^.*/ajax/.*$" ||
        req.url ~ "^.*/ahah/.*$" ||
        req.url ~ "^/entity-browser/.*$" ||
        req.url ~ "^/node/*/edit/.*$" ||
        req.url ~ "^/node/add/.*$" ||
        req.url ~ "^/system/files/.*$") {

        return (pass);
    }

    # Add an X-Forwarded-For header with the client IP address.
    if (req.restarts == 0) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        }
        else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }

    # Only allow PURGE requests from IP addresses in the 'purge' ACL.s
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed."));
        }

        return (purge);
    }

    # Only allow BAN requests from IP addresses in the 'purge' ACL.
    if (req.method == "BAN") {

        # Same ACL check as above:
        if (!client.ip ~ purge) {
            return (synth(403, "Not allowed."));
        }

        # Logic for the ban, using the Cache-Tags header. For more info
        # see https://github.com/geerlingguy/drupal-vm/issues/397.
        if (req.http.Purge-Cache-Tags) {
            ban("obj.http.Cache-Tags ~ " + req.http.Purge-Cache-Tags);
        }
        else {
            return (synth(403, "Purge-Cache-Tags header missing."));
        }

        # Throw a synthetic page so the request won't go to the backend.
        return (synth(200, "Ban added."));
    }

    # Only cache GET and HEAD requests (pass through POST requests).
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Remove all cookies that are not necessary for Drupal to work properly.
    # Since it would be cumbersome to REMOVE certain cookies, we specify
    # which ones are of interest to us, and remove all others. In this particular
    # case we leave SESS, SSESS and NO_CACHE cookies used by Drupal's administrative
    # interface. Cookies in cookie header are delimited with ";", so when there are
    # many cookies, the header looks like "Cookie1=value1; Cookie2=value2; Cookie3..."
    # and so on. That allows us to work with ";" to split cookies into individual
    # ones.

    if (req.http.Cookie) {
        if (req.url ~ "(?i)\.(css|js|jpg|jpeg|gif|png|ico)(\?.*)?$") {
            unset req.http.Cookie;
        }

        set req.http.Cookie = ";" + req.http.Cookie;
        set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
        set req.http.Cookie = regsuball(req.http.Cookie, ";(SESS[a-z0-9]+|SSESS[a-z0-9]+|NO_CACHE)=", "; \1=");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

        if (req.http.Cookie == "") {
            unset req.http.Cookie;
        }
        else {
            return (pass);
        }
    }

    # Handle compression correctly. Different browsers send different
    # "Accept-Encoding" headers, even though they mostly all support the same
    # compression mechanisms. By consolidating these compression headers into
    # a consistent format, we can reduce the size of the cache and get more hits.
    # @see: http:// varnish.projects.linpro.no/wiki/FAQ/Compression
    if (req.http.Accept-Encoding) {
        if (req.http.Accept-Encoding ~ "gzip") {
            # If the browser supports it, we'll use gzip.
            set req.http.Accept-Encoding = "gzip";
        }
        else if (req.http.Accept-Encoding ~ "deflate") {
            # Next, try deflate if it is supported.
            set req.http.Accept-Encoding = "deflate";
        }
        else {
            # Unknown algorithm. Remove it and send unencoded.
            unset req.http.Accept-Encoding;
        }
    }
}

sub vcl_backend_response {
    # Happens after we have read the response headers from the backend.
    #
    # Here you clean the response headers, removing silly Set-Cookie headers
    # and other mistakes your backend does.

    if (beresp.ttl > 0s) {
        set beresp.http.x-obj-ttl = beresp.ttl + "s";
    }
    else {
        set beresp.ttl = 5m;
        set beresp.http.x-obj-ttl = beresp.ttl;
    }

    # Set ban-lurker friendly custom headers.
    set beresp.http.X-Url = bereq.url;
    set beresp.http.X-Host = bereq.http.host;

    # Cache 404s, 301s, at 500s with a short lifetime to protect the backend.
    if (beresp.status == 404 || beresp.status == 301 || beresp.status == 500) {
        set beresp.ttl = 10m;
    }

    # Enable streaming directly to backend for BigPipe responses.
    if (beresp.http.Surrogate-Control ~ "BigPipe/1.0") {
        set beresp.do_stream = true;
        set beresp.ttl = 0s;
    }

    # Don't allow static files to set cookies.
    # (?i) denotes case insensitive in PCRE (perl compatible regular expressions).
    # This list of extensions appears twice, once here and again in vcl_recv so
    # make sure you edit both and keep them equal.
    if (bereq.url ~ "(?i)\.(pdf|asc|dat|txt|doc|xls|ppt|tgz|csv|png|gif|jpeg|jpg|ico|swf|css|js)(\?.*)?$") {
        unset beresp.http.set-cookie;
    }

  # Allow items to remain in cache up to 6 hours past their cache expiration.
  set beresp.grace = 6h;
}

sub vcl_deliver {
    #Happens when we have all the pieces we need, and are about to send the
    #response to the client.

    #You can do accounting or modifying the final object here.
    unset resp.http.X-Url;
    unset resp.http.X-Host;
    unset resp.http.Purge-Cache-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Generator;

    if (obj.hits > 0) {
        set resp.http.Cache-Tags = "HIT";
        set resp.http.X-Varnish-Cache = "HIT";
    }
    else {
        set resp.http.Cache-Tags = "MISS";
        set resp.http.X-Varnish-Cache = "MISS";
    }

    if (resp.http.x-obj-ttl) {
        set resp.http.Expires = "" + (now + std.duration(resp.http.x-obj-ttl, 3600s));
        unset resp.http.x-obj-ttl;
    }
}

sub vcl_backend_error {
    set beresp.http.Content-Type = "text/html; charset=utf-8";
    set beresp.http.Retry-After = "5";

    synthetic({"<html><body><h1>We are coming back soon!</h1></body></html>"} );

    return (deliver);
}

## Handle 401 authentication error
sub vcl_synth {
    if (resp.status == 601) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.host + req.url;
    }

    return (deliver);
}

sub vcl_hash {
    if (req.http.X-UA-Device) {
        hash_data(req.http.X-UA-Device);
    }
}