package sigtesting

import java.io.{ByteArrayInputStream, File, FileInputStream, StringWriter}
import java.lang.Object
import java.nio.file.{Files, Paths}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.{KeyStore, PrivateKey}
import java.util.{ArrayList, Collections}
import javax.xml.crypto.dsig.dom.{DOMSignContext, DOMValidateContext}
import javax.xml.crypto.dsig.keyinfo.KeyInfo
import javax.xml.crypto.dsig.spec.{C14NMethodParameterSpec, TransformParameterSpec}
import javax.xml.crypto.dsig.{CanonicalizationMethod, DigestMethod, SignedInfo, SignatureMethod, Transform, XMLSignatureFactory, XMLSignature}
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.{Document, Node}
import org.apache.xml.security.utils.XMLUtils

def getSignedXMLMessageString(xmlInputPathAndFile: String): String = {
  val privateKey = getPrivateKey("./testdata/devtest.p12")
  if (privateKey == null) {
    println("null private key")
    sys.exit(1)
  }
  val signedInfo = getCertificateSignedInformation()

  val certificateKeyInformation = getCertificateX509Information("./testdata/devtest.cer")
  if (certificateKeyInformation == null) {
    println("null certificateKeyInformation")
    sys.exit(1)
  }

  // Load and parse XML document into DOM Document
  val unmarshaledXMLDocument = unmarshalXMLFile(xmlInputPathAndFile)

  // Find the XML document placeholder tag for the enveloped signature
  val signatureParentNode = unmarshaledXMLDocument.getElementsByTagName("head:Sgntr").item(0)
  if (signatureParentNode == null) {
    println("null signatureParentNode")
    sys.exit(1)
  }

  return applySignature(
    privateKey,
    signatureParentNode,
    signedInfo,
    certificateKeyInformation,
    unmarshaledXMLDocument,
  )
}

def unmarshalXMLFile(path: String): Document = {
  val content = new String(Files.readAllBytes(Paths.get(path)))
  return parseXML(content)
}

def parseXML(input: String): Document = {
  // val factory = DocumentBuilderFactory.newInstance()
  // val builder = factory.newDocumentBuilder()
  //
  // return builder.parse(new ByteArrayInputStream(input.trim().getBytes()))

  return XMLUtils.read(new ByteArrayInputStream(input.trim().getBytes()), true)
}

def getPrivateKey(privateKeyPathAndFilename: String): PrivateKey = {
  val keystore: KeyStore = KeyStore.getInstance("PKCS12")

  // Open the PKCS512 keystore file to access the private key
  val kis = new FileInputStream(new File(privateKeyPathAndFilename))

  keystore.load(kis, "devtest".toCharArray())
  kis.close()

  // Retrieve private key from keystore
  val keyAlias = "devtest"

  return keystore.getKey(keyAlias, "devtest".toCharArray()).asInstanceOf[PrivateKey]
}

def getXMLSignatureFactory(): XMLSignatureFactory = {
   return XMLSignatureFactory.getInstance("DOM")
}

def getCertificateSignedInformation(): SignedInfo = {
  val xmlSignatureFactory = getXMLSignatureFactory()

  // RTPS uses EXCLUSIVE Canonicalization for XML enveloped signatures and SHA256 hashing
  val envTransform = xmlSignatureFactory.newTransform(Transform.ENVELOPED, null.asInstanceOf[TransformParameterSpec])
  val exc14n11Transform = xmlSignatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", null.asInstanceOf[TransformParameterSpec])

  val transforms = new ArrayList[Transform]()
  transforms.add(envTransform)
  transforms.add(exc14n11Transform)

  val digestMethod = xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null)
  val ref = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null)

  return xmlSignatureFactory.newSignedInfo(
    xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, null.asInstanceOf[C14NMethodParameterSpec]),
    xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
    Collections.singletonList(ref),
  )
}

def getPublicCertificate(certificatePathAndFilename: String): X509Certificate = {
  val xmlSignatureFactory = getXMLSignatureFactory()

  // Open the public certificate used to retrieve X509 data for signature tags in XML
  val publicCertificateFileStream = new FileInputStream(new File(certificatePathAndFilename))
  val certificateFactory = CertificateFactory.getInstance("X.509")

  return certificateFactory.generateCertificate(publicCertificateFileStream).asInstanceOf[X509Certificate]
}

def getCertificateX509Information(certificatePathAndFilename: String): KeyInfo = {
  val xmlSignatureFactory = getXMLSignatureFactory()

  // Open the public certificate used to retrieve X509 data for signature tags in XML
  val publicCertificateFileStream = new FileInputStream(new File(certificatePathAndFilename))
  val certificateFactory = CertificateFactory.getInstance("X.509")

  val cert = certificateFactory.generateCertificate(publicCertificateFileStream).asInstanceOf[X509Certificate]

  val kif = xmlSignatureFactory.getKeyInfoFactory()
  val x509Issuer = kif.newX509IssuerSerial(cert.getSubjectX500Principal().getName(), cert.getSerialNumber())

  // Store Distinguished Name (DN), Certificate Issuer and Serial Number into KeyInfo
  val x509Content = new ArrayList[Object]()
  x509Content.add(cert.getSubjectX500Principal().getName())
  x509Content.add(x509Issuer)

  val xd = kif.newX509Data(x509Content)

  // Create a KeyInfo and add the KeyValue to it. This is the X509 info used in the XML enveloped signature
  return kif.newKeyInfo(Collections.singletonList(xd))
}

def applySignature(
  privateKey: PrivateKey,
  signatureParentNode: Node,
  signedInfo: SignedInfo,
  certificateKeyInformation: KeyInfo,
  documentObjectModel: Document,
): String = {
  // Create a DOMSignContext and specify the RSA PrivateKey and location of the resulting XMLSignature's parent element
  val dsc = new DOMSignContext(privateKey, signatureParentNode)

  // Create the XMLSignature (but don't sign it yet)
  val xmlSignatureFactory = getXMLSignatureFactory()
  val signature = xmlSignatureFactory.newXMLSignature(signedInfo, certificateKeyInformation)

  // Sign the document now
  signature.sign(dsc)

  val out = new StringWriter()
  val result = new StreamResult(out)

  // The transformer will take the DOM and make an XML string out of it
  val tf = TransformerFactory.newInstance()
  val trans = tf.newTransformer()
  trans.transform(new DOMSource(documentObjectModel), result)

  // Signing successful. Return signed XML document as String
  return out.toString()
}

def isSignatureValid(certificatePathAndFilename: String, doc: Document): Boolean = {
  val xmlSignatureFactory = getXMLSignatureFactory()
  val publicCertificate = getPublicCertificate(certificatePathAndFilename)

  var valid = false

  // Find Signature node within the DOM
  val nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
  if (nl.getLength() > 0) {
    // Create a DOMValidateContext. Pass the certificate's public key and signature node
    val validateContext = new DOMValidateContext(publicCertificate.getPublicKey(), nl.item(0))
    val signatureFactory = XMLSignatureFactory.getInstance("DOM")

    // Retrieve the document’s signature
    val signature = signatureFactory.unmarshalXMLSignature(validateContext)

    // Validate document’s signature against the certificate’s public key
    valid = signature.validate(validateContext)
  }

  return valid
}
