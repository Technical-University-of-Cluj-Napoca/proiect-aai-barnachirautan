# django_xss
# Sursa: https://docs.djangoproject.com/en/stable/topics/security/
# Data accesarii: 2026-05-31

Cross site scripting (XSS) protection
¶
XSS attacks allow a user to inject client side scripts into the browsers of
other users. This is usually achieved by storing the malicious scripts in the
database where it will be retrieved and displayed to other users, or by getting
users to click a link which will cause the attacker’s JavaScript to be executed
by the user’s browser. However, XSS attacks can originate from any untrusted
source of data, such as cookies or web services, whenever the data is not
sufficiently sanitized before including in a page.
Using Django templates protects you against the majority of XSS attacks.
However, it is important to understand what protections it provides
and its limitations.
Django templates
escape specific characters
which are particularly dangerous to HTML. While this protects users from most
malicious input, it is not entirely foolproof. For example, it will not
protect the following:
<style class={{ var }}>...</style>
If
var
is set to
'class1
onmouseover=javascript:func()'
, this can
result in unauthorized JavaScript execution, depending on how the browser
renders imperfect HTML. (Quoting the attribute value would fix this case.)
It is also important to be particularly careful when using
is_safe
with
custom template tags, the
safe
template tag,
mark_safe
, and when autoescape is turned off.
In addition, if you are using the template system to output something other
than HTML, there may be entirely separate characters and words which require
escaping.
You should also be very careful when storing HTML in the database, especially
when that HTML is retrieved and displayed.