# django_ssl
# Sursa: https://docs.djangoproject.com/en/stable/topics/security/
# Data accesarii: 2026-05-31

SSL/HTTPS
¶
It is always better for security to deploy your site behind HTTPS. Without
this, it is possible for malicious network users to sniff authentication
credentials or any other information transferred between client and server, and
in some cases –
active
network attackers – to alter data that is sent in
either direction.
If you want the protection that HTTPS provides, and have enabled it on your
server, there are some additional steps you may need:
If necessary, set
SECURE_PROXY_SSL_HEADER
, ensuring that you have
understood the warnings there thoroughly. Failure to do this can result
in CSRF vulnerabilities, and failure to do it correctly can also be
dangerous!
Set
SECURE_SSL_REDIRECT
to
True
, so that requests over HTTP
are redirected to HTTPS.
Please note the caveats under
SECURE_PROXY_SSL_HEADER
. For the
case of a reverse proxy, it may be easier or more secure to configure the
main web server to do the redirect to HTTPS.
Use ‘secure’ cookies.
If a browser connects initially via HTTP, which is the default for most
browsers, it is possible for existing cookies to be leaked. For this reason,
you should set your
SESSION_COOKIE_SECURE
and
CSRF_COOKIE_SECURE
settings to
True
. This instructs the
browser to only send these cookies over HTTPS connections. Note that this
will mean that sessions will not work over HTTP, and the CSRF protection will
prevent any POST data being accepted over HTTP (which will be fine if you are
redirecting all HTTP traffic to HTTPS).
Use
HTTP Strict Transport Security
(HSTS)
HSTS is an HTTP header that informs a browser that all future connections to
a particular site should always use HTTPS. Combined with redirecting requests
over HTTP to HTTPS, this will ensure that connections always enjoy the added
security of SSL provided one successful connection has occurred. HSTS may
either be configured with
SECURE_HSTS_SECONDS
,
SECURE_HSTS_INCLUDE_SUBDOMAINS
, and
SECURE_HSTS_PRELOAD
, or on the web server.