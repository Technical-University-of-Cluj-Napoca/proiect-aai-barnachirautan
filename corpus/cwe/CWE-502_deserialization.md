# CWE-502_deserialization
# Sursa: https://cwe.mitre.org/data/definitions/502.html
# Data accesarii: 2026-05-29

## Description
Description
The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.
## Alternate_Terms
Alternate Terms
Marshaling/Marshalling, Unmarshaling/Unmarshalling
Marshaling and unmarshaling are effectively synonyms for serialization and deserialization, respectively.
Pickling, Unpickling
In Python, the "pickle" functionality is used to perform serialization and deserialization.
PHP Object Injection
Some PHP application researchers use this term when attacking unsafe use of the unserialize() function; but it is also used for
CWE-915
.
## Potential_Mitigations
Potential Mitigations
Phase(s)
Mitigation
Architecture and Design; Implementation
If available, use the signing/sealing features of the programming language to assure that deserialized data has not been tainted. For example, a hash-based message authentication code (HMAC) could be used to ensure that data has not been modified.
Implementation
When deserializing data, populate a new object rather than just deserializing. The result is that the data flows through safe input validation and that the functions are safe.
Implementation
Explicitly define a final object() to prevent deserialization.
Architecture and Design; Implementation
Make fields transient to protect them from deserialization.
An attempt to serialize and then deserialize a class containing transient fields will result in NULLs where the transient data should be. This is an excellent way to prevent time, environment-based, or sensitive variables from being carried over and used improperly.
Implementation
Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends. This limits the potential for unintended or unauthorized types and gadgets to be leveraged by the attacker. Add only acceptable classes to an allowlist. Note: new gadgets are constantly being discovered, so this alone is not a sufficient mitigation.
Architecture and Design; Implementation
Employ cryptography of the data or code for protection. However, it's important to note that it would still be client-side security. This is risky because if the client is compromised then the security implemented on the client (the cryptography) can be bypassed.
Operation
Strategy:
Firewall
Use an application firewall that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth [
REF-1481
].
Effectiveness: Moderate
Note:
An application firewall might not cover all possible input vectors. In addition, attack techniques might be available to bypass the protection mechanism, such as using malformed inputs that can still be processed by the component that receives those inputs. Depending on functionality, an application firewall might inadvertently reject or modify legitimate requests. Finally, some manual effort may be required for customization.
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
913
Improper Control of Dynamically-Managed Code Resources
PeerOf
Base - a weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource.
915
Improperly Controlled Modification of Dynamically-Determined Object Attributes
Relevant to the view "Software Development" (View-699)
Nature
Type
ID
Name
MemberOf
Category - a CWE entry that contains a set of other entries that share a common characteristic.
399
Resource Management Errors
Relevant to the view "Weaknesses for Simplified Mapping of Published Vulnerabilities" (View-1003)
Nature
Type
ID
Name
ChildOf
Class - a weakness that is described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource.
913
Improper Control of Dynamically-Managed Code Resources
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
Architecture and Design
OMISSION: This weakness is caused by missing a security tactic during the architecture and design phase.
Implementation
## Applicable_Platforms
Applicable Platforms
This listing shows possible areas for which the given
                        weakness could appear. These
                        may be for specific named Languages, Operating Systems, Architectures, Paradigms,
                        Technologies,
                        or a class of such platforms. The platform is listed along with how frequently the given
                        weakness appears for that instance.
Languages
Java
(Undetermined Prevalence)
Ruby
(Undetermined Prevalence)
PHP
(Undetermined Prevalence)
Python
(Undetermined Prevalence)
JavaScript
(Undetermined Prevalence)
Technologies
Class: Not Technology-Specific
(Undetermined Prevalence)
Class: ICS/OT
(Often Prevalent)
AI/ML
(Often Prevalent)
## Demonstrative_Examples
Demonstrative Examples
Example 1
This code snippet deserializes an object from a file and uses it as a UI button:
(bad code)
Example Language:
Java
try {
File file = new File("object.obj");
ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
javax.swing.JButton button = (javax.swing.JButton) in.readObject();
in.close();
}
This code does not attempt to verify the source or contents of the file before deserializing it. An attacker may be able to replace the intended file with a file that contains arbitrary malicious code which will be executed when the button is pressed.
To mitigate this, explicitly define final readObject() to prevent deserialization. An example of this is:
(good code)
Example Language:
Java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
throw new java.io.IOException("Cannot be deserialized"); }
Example 2
In Python, the Pickle library handles the serialization and deserialization processes. In this example derived from [
REF-467
], the code receives and parses data, and afterwards tries to authenticate a user based on validating a token.
(bad code)
Example Language:
Python
try {
class ExampleProtocol(protocol.Protocol):
def dataReceived(self, data):
# Code that would be here would parse the incoming data
# After receiving headers, call confirmAuth() to authenticate
def confirmAuth(self, headers):
try:
token = cPickle.loads(base64.b64decode(headers['AuthToken']))
if not check_hmac(token['signature'], token['data'], getSecretKey()):
raise AuthFail
self.secure_data = token['data']
except:
raise AuthFail
}
Unfortunately, the code does not verify that the incoming data is legitimate. An attacker can construct a illegitimate, serialized object "AuthToken" that instantiates one of Python's subprocesses to execute arbitrary commands. For instance,the attacker could construct a pickle that leverages Python's subprocess module, which spawns new processes and includes a number of arguments for various uses. Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.
## Detection_Methods
Detection
        Methods
Method
Details
Automated Static Analysis
Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)
Effectiveness: High