# xml-signatures-mastercard

Mastercard offers a Java library for [signing and validating ISO 20022 messages](https://github.com/Mastercard/xmlsignverify-core-java).
This is a helpful example for other languages, but the .jar doesn't seem published anywhere. This project is an example of using the code
in Scala, which may help others.

This project also tries to sign using TCH's recommended code, which doesn't work.

## Updating Mastercard library

You need to `mvn package` inside the Mastercard project and copy the `.jar` over to the `lib/` folder. sbt will automatically check that directory.

## Example

```
sbt:sigtesting> run
[info] compiling 3 Scala sources to /Users/adam/code/src/github.com/adamdecaf/xml-signatures-mastercard/target/scala-3.2.2/classes ...
[info] running sigtesting.main$package
BAH_NAME namespace URI: urn:iso:std:iso:20022:tech:xsd:head.001.001.01
BAH_NAME local part: AppHdr
WS_SECURITY_NAME namespace URI: urn:iso:std:iso:20022:tech:xsd:head.001.001.01
WS_SECURITY_NAME local part: Sgntr
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
found 1 BAH nodes
Signature is valid
[success] Total time: 5 s, completed Mar 23, 2023, 10:13:55 AM
```
