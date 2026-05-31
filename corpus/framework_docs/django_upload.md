# django_upload
# Sursa: https://docs.djangoproject.com/en/stable/topics/security/
# Data accesarii: 2026-05-31

User-uploaded content
¶
Note
Consider
serving static files from a cloud service or CDN
to avoid some of these issues.
If your site accepts file uploads, it is strongly advised that you limit
these uploads in your web server configuration to a reasonable
size in order to prevent denial of service (DOS) attacks. In Apache, this
can be easily set using the
LimitRequestBody
directive. You should not rely
solely on
DATA_UPLOAD_MAX_MEMORY_SIZE
nor
FILE_UPLOAD_MAX_MEMORY_SIZE
.
If you are serving your own static files, be sure that handlers like Apache’s
mod_php
, which would execute static files as code, are disabled. You
don’t want users to be able to execute arbitrary code by uploading and
requesting a specially crafted file.
Django’s media upload handling poses some vulnerabilities when that media is
served in ways that do not follow security best practices. Specifically, an
HTML file can be uploaded as an image if that file contains a valid PNG
header followed by malicious HTML. This file will pass verification of the
library that Django uses for
ImageField
image
processing (Pillow). When this file is subsequently displayed to a
user, it may be displayed as HTML depending on the type and configuration of
your web server.
No bulletproof technical solution exists at the framework level to safely
validate all user uploaded file content, however, there are some other steps
you can take to mitigate these attacks:
One class of attacks can be prevented by always serving user uploaded
content from a distinct top-level or second-level domain. This prevents
any exploit blocked by
same-origin policy
protections such as cross
site scripting. For example, if your site runs on
example.com
, you
would want to serve uploaded content (the
MEDIA_URL
setting)
from something like
usercontent-example.com
. It’s
not
sufficient to
serve content from a subdomain like
usercontent.example.com
.
Beyond this, applications may choose to define a list of allowable
file extensions for user uploaded files and configure the web server
to only serve such files.