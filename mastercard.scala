package sigtesting

import java.lang.Object
import java.security.PublicKey
import java.security.cert.X509Certificate
import org.w3c.dom.Document
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.keys.content.x509.XMLX509SKI
import com.mastercard.ap.security.bah.utility.XmlSignUtil
import com.mastercard.ap.security.bah.utility.context.Constants.{BAH_NAME, WS_SECURITY_NAME}
import com.mastercard.ap.security.bah.utility.info.{ReferenceSignInfo, SignatureInfo, SignatureKeyInfo}

def debugMastercard(): Unit = {
  println(s"BAH_NAME namespace URI: ${BAH_NAME.getNamespaceURI()}")
  println(s"BAH_NAME local part: ${BAH_NAME.getLocalPart()}")

  println(s"WS_SECURITY_NAME namespace URI: ${WS_SECURITY_NAME.getNamespaceURI()}")
  println(s"WS_SECURITY_NAME local part: ${WS_SECURITY_NAME.getLocalPart()}")
}

def signWithMastercard(): Document = {
  debugMastercard()

  org.apache.xml.security.Init.init()

  val doc = unmarshalXMLFile("./testdata/pacs.008-test.xml")
  // val doc = unmarshalXMLFile("./testdata/source-unsigned.xml")
  val bahNodes = doc.getElementsByTagNameNS(BAH_NAME.getNamespaceURI(), BAH_NAME.getLocalPart())
  println(s"found ${bahNodes.getLength()} BAH nodes")

  val x509Certificate = getPublicCertificate("./testdata/devtest.cer")
  // val x509Certificate = getPublicCertificate("../../configs/simulation/Open_Test_Solutions_Public_Key.crt")

  val privateKey = getPrivateKey("./testdata/devtest.p12")
  // val privateKey = getPrivateKey("../../configs/simulation/devtest.p12")
  if (privateKey == null) {
    println("null private key")
    sys.exit(1)
  }

  val signatureKeyInfo = SignatureKeyInfo.builder()
    .privateKey(privateKey)
    .skiIdBytes(getSKIBytesFromCert(x509Certificate))
    .build()

  val referenceSignInfo = ReferenceSignInfo.builder()
    .digestMethodAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256")
    .transformAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#")
    .build()

  val signatureInfo = SignatureInfo.builder()
    .appHdrReferenceSignInfo(referenceSignInfo)
    .documentReferenceSignInfo(referenceSignInfo)
    .keyReferenceSignInfo(referenceSignInfo)
    .signatureCanonicalizationMethodAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#")
    .signatureExclusionTransformer("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    .signatureMethodAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    .build()

  return XmlSignUtil.sign(doc, signatureInfo, signatureKeyInfo)
}

def getSKIBytesFromCert(cert: X509Certificate): Array[Byte] = {
  // taken from mastercard tests

  if (cert.getVersion() < 3) {
    val exArgs = Array[Object](Integer.valueOf(cert.getVersion()))
    throw new XMLSecurityException("certificate.noSki.lowVersion", exArgs)
  }

  val extensionValue: Array[Byte] = cert.getExtensionValue(XMLX509SKI.SKI_OID)
  if (extensionValue == null) {
    throw new XMLSecurityException("certificate.noSki.null")
  }

  val skidValue = new Array[Byte](extensionValue.length - 4)

  System.arraycopy(extensionValue, 4, skidValue, 0, skidValue.length)

  return skidValue
}

def verifyWithMastercard(doc: Document): Unit = {
  val publicCertificate = getPublicCertificate("./testdata/devtest.cer")
  // val publicCertificate = getPublicCertificate("../../configs/simulation/Open_Test_Solutions_Public_Key.crt")

  val valid = XmlSignUtil.verify(doc, publicCertificate.getPublicKey())
  if (valid) {
    println("Signature is valid")
  } else {
    println("Invalid Signature")
    sys.exit(1)
  }
}
