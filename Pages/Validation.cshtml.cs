using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;


namespace SIPVS_NT.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]

    // Logger class for logging
    public class Logger
    {
        private readonly string logFilePath;

        public Logger(string logFilePath)
        {
            this.logFilePath = logFilePath;

            // Create or overwrite the log file at the start of the program
            File.Create(logFilePath).Close();
        }

        public void Log(string message)
        {
            try
            {
                // Append to the log file
                using (StreamWriter sw = File.AppendText(logFilePath))
                {
                    // if needed, you can add a timestamp to the message
                    sw.WriteLine(message);
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions, for example, print to console
                Console.WriteLine($"Error logging: {ex.Message}");
            }
        }
    }


    public class ValidationModel : PageModel
    {
        // Folder path where the files are located
        private readonly string folderPath = "signatures";

        // Specify the path for the log file
        private readonly string logFilePath = "validation_results.log";
        private string timestampCrlUrl = "http://test.ditec.sk/TSAServer/crl/dtctsa.crl";
        private string signCrlUrl = "http://test.ditec.sk/DTCCACrl/DTCCACrl.crl";

        // Event handler for the button click
        public IActionResult OnPostLoadFiles()
        {
            try
            {
                // Create an instance of the Logger
                Logger logger = new Logger(logFilePath);

                // Get all files in the folder
                //string[] files = Directory.GetFiles(folderPath);
                string[] files = Directory.GetFiles(folderPath).OrderBy(f => f).ToArray();

                // Loop through each file
                foreach (var filePath in files)
                {
                    // get file name
                    string fileName = Path.GetFileName(filePath);
                    logger.Log("\n--------------------------------------------------");
                    logger.Log($"Validácia súboru: {fileName}");
                    
                    // Initialize the verification flag
                    bool validationPassed = true;

                    // Verify conditions one by one
                    // Verification of the data envelope - Overenie dátovej obálky
                    if (!DataEnvelope(filePath, "xzep", "http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0"))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie dátovej obálky nebolo úspešné - neplatná hodnota atribútu xmlns:xzep v koreňovom prvku.");
                        continue; // Stop verification for this file
                    }
                    if (!DataEnvelope(filePath, "ds", "http://www.w3.org/2000/09/xmldsig#"))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie dátovej obálky nebolo úspešné - neplatná hodnota atribútu xmlns:ds v koreňovom prvku.");
                        continue; // Stop verification for this file
                    }

                    // Verification XML Signature 
                    if (!Signature(filePath, logger))
                    {
                        validationPassed = false;
                        //logger.Log($"Overenie XML Signature nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    // Verification Core Validation 
                    if (!CoreValidation(filePath, logger))
                    {
                        validationPassed = false;
                        //logger.Log($"Overenie Core Validation nebolo úspešné ");
                        continue; // Stop verification for this file
                    }

                    // verification of other elements
                    if (!CheckElements(filePath, logger))
                    {
                        validationPassed = false;
                        //logger.Log($"Overenie other elements nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    if (!checkTimestamp(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie časovej pečiatky nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    if (!checkMessageImprint(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie Messageimprint nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    if (!checkSignCert(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie platnosti podpisového certifikátu nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    // pridanie dalsieho overenia

                    // If all conditions passed, log successful validation
                    if (validationPassed)
                    {
                        logger.Log($"Súbor bol úspešne validovaný: {fileName}");
                    }
                }

                // Logic or return a response if needed
                return Content("<script>alert('Process finished'); window.location.href='/Validation'</script>",
                    "text/html");
            }
            catch (Exception ex)
            {
                // Handle exceptions, return an error response
                return new BadRequestObjectResult($"Error validating signatures: {ex.Message}");
            }
        }

        // Method for verifying the data envelope - Overenie dátovej obálky
        private bool DataEnvelope(string filePath, string prefix, string expectedUri)
        {
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);
            // Get the root element
            XElement rootElement = xmlDoc.Root;
            
            XAttribute namespaceAttribute = rootElement.Attribute(XNamespace.Xmlns + prefix);

            if (namespaceAttribute == null || namespaceAttribute.Value != expectedUri)
            {
                return false;
            }
            return true;
        }

        // Method for verifying the XML Signature
        private bool Signature(string filePath, Logger logger)
        {
            string[] SUPPORTED_SIGNATURE_ALGORITHMS =
            {
                "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            };

            string[] SUPPORTED_DIGEST_ALGORITHMS =
            {
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmldsig-more#sha224",
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "https://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512"
            };

            string[] SUPPORTED_TRANSFORM_ALGORITHMS =
            {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                "http://www.w3.org/2000/09/xmldsig#base64"
            };

            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);

            // Define the namespace
            var namespaceId = new XmlNamespaceManager(new NameTable());
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            // checking the contents of ds:SignatureMethod a ds:CanonicalizationMethod 
            string signatureMethodAlgorithm = xmlDoc
                .XPathSelectElement("//ds:SignedInfo/ds:SignatureMethod", namespaceId)?.Attribute("Algorithm")?.Value;
            string canonicalizationMethodAlgorithm = xmlDoc
                .XPathSelectElement("//ds:SignedInfo/ds:CanonicalizationMethod", namespaceId)?.Attribute("Algorithm")
                ?.Value;

            if (!SUPPORTED_SIGNATURE_ALGORITHMS.Contains(signatureMethodAlgorithm))
            {
                logger.Log($"Overenie XML Signature: ds:SignatureMethod - nepodporovaný transformačný algoritmus");
                //Console.WriteLine($"XML Signature Verification: ds:SignatureMethod Unsupported transform algorithm");
                return false;
            }

            if (canonicalizationMethodAlgorithm != "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
            {
                logger.Log($"Overenie XML Signature: ds:CanonicalizationMethod - nepodporovaný transformačný algoritmus");
                //Console.WriteLine($"XML Signature Verification: ds:CanonicalizationMethod Unsupported transform algorithm");
                return false;
            }

            // select all references within ds:SignedInfo
            var references = xmlDoc.XPathSelectElements("//ds:SignedInfo/ds:Reference", namespaceId);

            foreach (var reference in references)
            {
                // Check ds:Transforms
                var transforms = reference.XPathSelectElements("ds:Transforms/ds:Transform", namespaceId);
                foreach (var transform in transforms)
                {
                    string transformAlgorithm = transform.Attribute("Algorithm")?.Value;
                    if (!SUPPORTED_TRANSFORM_ALGORITHMS.Contains(transformAlgorithm))
                    {
                        logger.Log($"Overenie XML Signature: ds:Transforms - nepodporovaný transformačný algoritmus");
                        //Console.WriteLine($"XML Signature Verification:  ds:Transforms Unsupported transform algorithm");
                        return false; // Unsupported transform algorithm found
                    }
                }

                // Check ds:DigestMethod
                string digestAlgorithm = reference.XPathSelectElement("ds:DigestMethod", namespaceId)
                    ?.Attribute("Algorithm")?.Value;
                if (!SUPPORTED_DIGEST_ALGORITHMS.Contains(digestAlgorithm))
                {
                    logger.Log($"Overenie XML Signature: ds:DigestMethod - nepodporovaný transformačný algoritmus");
                    //Console.WriteLine($"XML Signature Verification: ds:DigestMethod Unsupported digest algorithm");
                    return false;
                }
            }
            return true; // All references pass the checks
        }

        private bool CoreValidation(string filePath, Logger logger)
        {
            // Load XML content from the file
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);

            // Define the namespace
            var namespaceId = new XmlNamespaceManager(xmlDoc.NameTable);
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceId.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            //check ds:SignedInfo References
            XmlNode signedInfoN = xmlDoc.SelectSingleNode(@"//ds:SignedInfo", namespaceId);
            XmlNodeList referenceElements = signedInfoN.SelectNodes(@"//ds:Reference", namespaceId);

            //Reference in SignedInfo
            foreach (XmlNode reference in referenceElements)
            {
                // URI dereferencing
                String ReferenceURI = reference.Attributes.GetNamedItem("URI").Value;
                ReferenceURI = ReferenceURI.Substring(1);

                // Extract digestMethod and digestMethodAlgorithm and dsDigestValue
                XmlNode digestMethod = reference.SelectSingleNode("ds:DigestMethod", namespaceId);
                String digestMethodAlgorithm = digestMethod.Attributes.GetNamedItem("Algorithm").Value;
                string dsDigestValue = reference.SelectSingleNode("ds:DigestValue", namespaceId).InnerText;

                if (ReferenceURI.StartsWith("ManifestObject"))
                {
                    //get Manifest XML and check DigestValue
                    string manifestXML = xmlDoc
                        .SelectSingleNode("//ds:Manifest[@Id='" + ReferenceURI + "']", namespaceId).OuterXml;
                    MemoryStream streamManifest = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(manifestXML));

                    // Canonicalization – http://www.w3.org/TR/2001/REC-xml-c14n-20010315
                    XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
                    transform.LoadInput(streamManifest);
                    HashAlgorithm hash = null;

                    // Select the appropriate hash algorithm based on digestMethodAlgorithm
                    switch (digestMethodAlgorithm)
                    {
                        case "http://www.w3.org/2000/09/xmldsig#sha1":
                            hash = new SHA1Managed();
                            break;
                        case "http://www.w3.org/2001/04/xmlenc#sha256":
                            hash = new SHA256Managed();
                            break;
                        case "http://www.w3.org/2001/04/xmldsig-more#sha384":
                            hash = new SHA384Managed();
                            break;
                        case "http://www.w3.org/2001/04/xmlenc#sha512":
                            hash = new SHA512Managed();
                            break;
                    }

                    if (hash == null)
                    {
                        logger.Log($"Overenie Core Validation nebolo úspešné - nesprávny algoritmus hash {digestMethodAlgorithm}");
                        //Console.WriteLine(
                        //    "URI dereferencing, canonicalization of referenced ds:Manifest elements and validation of ds:DigestValue values");
                        //Console.WriteLine($"Incorrect hash algorithm {digestMethodAlgorithm}");
                        return false;
                    }

                    byte[] digest = transform.GetDigestedOutput(hash);
                    string result = Convert.ToBase64String(digest);

                    if (!result.Equals(dsDigestValue))
                    {
                        logger.Log($"Overenie Core Validation nebolo úspešné - DigestValue sa nezhoduje s výpočtom Manifest");
                        //Console.WriteLine(
                        //    "URI dereferencing, canonicalization of referenced ds:Manifest elements and validation of ds:DigestValue values");
                        //Console.WriteLine("DigestValue does not match with the computation of Manifest");
                        return false;
                    }
                }
            }

            // ds:SignedInfo canonicalization

            XmlNode x509CertificateElement =
                xmlDoc.SelectSingleNode(@"//ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaceId);
            if (x509CertificateElement == null)
            {
                logger.Log($"Overenie Core Validation nebolo úspešné - Neobsahuje element ds:X509Data");
                //Console.WriteLine("ds:SignedInfo canonicalization");
                //Console.WriteLine("Neobsahuje element ds:X509Data");
                return false;
            }

            // Extract the base64-encoded signature certificate from ds:X509Certificate element
            byte[] signatureCertificate = Convert.FromBase64String(xmlDoc
                .SelectSingleNode(@"//ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaceId).InnerText);

            // Extract the base64-encoded signature value
            byte[] signature =
                Convert.FromBase64String(xmlDoc.SelectSingleNode(@"//ds:SignatureValue", namespaceId).InnerText);

            // Extract the ds:SignedInfo element
            XmlNode signedInfoNnn = xmlDoc.SelectSingleNode(@"//ds:SignedInfo", namespaceId);
            // Extract the algorithm used for the digital signature in ds:SignedInfo
            string signedInfoSignatureAlg = xmlDoc.SelectSingleNode(@"//ds:SignedInfo/ds:SignatureMethod", namespaceId)
                .Attributes.GetNamedItem("Algorithm").Value;

            // ds:SignedInfo canonicalization
            XmlDsigC14NTransform transform1 = new XmlDsigC14NTransform(false);
            XmlDocument pom = new XmlDocument();
            pom.LoadXml(signedInfoNnn.OuterXml);
            transform1.LoadInput(pom);
            byte[] data = ((MemoryStream)transform1.GetOutput()).ToArray();

            string errorMessage = "";
            bool resultError = verifySign(signatureCertificate, signature, data, signedInfoSignatureAlg,
                out errorMessage);
            if (!resultError)
            {
                logger.Log($"Overenie Core Validation nebolo úspešné - zlyhalo overenie podpisu");
                //Console.WriteLine("Error " + errorMessage);
                return false;
            }

            // All references passed the validation
            return true;
        }

        private bool verifySign(byte[] certificateData, byte[] signature, byte[] data, string digestAlg,
            out string errorMessage)
        {
            try
            {
                Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo ski = Org.BouncyCastle.Asn1.X509
                    .X509CertificateStructure
                    .GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(certificateData)).SubjectPublicKeyInfo;
                Org.BouncyCastle.Crypto.AsymmetricKeyParameter pk =
                    Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(ski);

                string algStr = ""; //signature alg

                //find digest
                switch (digestAlg)
                {
                    case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                        algStr = "sha1";
                        break;
                    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                        algStr = "sha256";
                        break;
                    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                        algStr = "sha384";
                        break;
                    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                        algStr = "sha512";
                        break;
                }

                //find encryption
                switch (ski.AlgorithmID.ObjectID.Id)
                {
                    case "1.2.840.10040.4.1": //dsa
                        algStr += "withdsa";
                        break;
                    case "1.2.840.113549.1.1.1": //rsa
                        algStr += "withrsa";
                        break;
                    default:
                        errorMessage = "verifySign 5: Unknown key algId = " + ski.AlgorithmID.ObjectID.Id;
                        return false;
                }

                // Console.WriteLine("Hash digest pred decryptom: " + Convert.ToBase64String(data));


                errorMessage = "verifySign 8: Creating signer: " + algStr;
                Org.BouncyCastle.Crypto.ISigner verif = Org.BouncyCastle.Security.SignerUtilities.GetSigner(algStr);
                verif.Init(false, pk);
                verif.BlockUpdate(data, 0, data.Length);
                bool res = verif.VerifySignature(signature);

                //Console.WriteLine("Hodnota pk je: " + pk.GetHashCode());

                // Console.WriteLine("Hash digest po decrypte: " + Convert.ToBase64String(data));

                //Console.WriteLine("- ");
                //Console.WriteLine("Hodnota je " + res);
                //Console.WriteLine("- ");
                if (!res)
                {
                    errorMessage = "verifySign 9: VerifySignature=false: dataB64=" + Convert.ToBase64String(data) +
                                   Environment.NewLine + "signatureB64=" + Convert.ToBase64String(signature) +
                                   Environment.NewLine + "certificateDataB64=" +
                                   Convert.ToBase64String(certificateData);
                }

                return res;
            }
            catch (Exception ex)
            {
                errorMessage = "verifySign 10: " + ex.ToString();
                return false;
            }
        }

        private bool CheckElements(string filePath, Logger logger)
        {
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);

            var namespaceId = new XmlNamespaceManager(new NameTable());
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceId.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // ds:Signature check Id attribute 
            string dsSignatureId = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId)?.Attribute("Id")?.Value;
            if (dsSignatureId == null)
            {
                logger.Log("Error pri overovaní elementov - ds:Signature neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:Signature neobsahuje Id");
                return false;
            }

            XElement dsSignatureElement = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId);
            if (dsSignatureElement == null)
            {
                logger.Log("padlo to na ds:Signature");
                return false;
            }

            // ds:Signature check namespace xmlns:ds attribute
            XAttribute xmlnsDsAttribute = dsSignatureElement.Attribute(XNamespace.Xmlns + "ds");
            if (xmlnsDsAttribute == null)
            {
                logger.Log("Error pri overovaní elementov - ds:Signature neobsahuje specifikovany namespace xmlns:ds");
                //Console.WriteLine($"File: {filePath} Error: ds:Signature neobsahuje specifikovany namespace xmlns:ds");
                return false;
            }

            // ds:SignatureValue check Id attribute
            string dsSignatureValueId =
                xmlDoc.XPathSelectElement("//ds:SignatureValue", namespaceId)?.Attribute("Id")?.Value;
            if (dsSignatureValueId == null)
            {
                logger.Log("Error pri overovaní elementov - ds:SignatureValue neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:SignatureValue neobsahuje Id");
                return false;
            }

            XElement signedInfoElement = xmlDoc.XPathSelectElement("//ds:SignedInfo", namespaceId);
            IEnumerable<XElement> dsReferenceNodes =
                signedInfoElement.XPathSelectElements(".//ds:Reference", namespaceId);


            if (dsReferenceNodes == null || dsReferenceNodes.Count() < 1)
            {
                logger.Log("Error pri overovaní elementov - ds:SignedInfo neobsahuje ds:Reference");
                //Console.WriteLine($"File: {filePath} Error: ds:SignedInfo neobsahuje ds:Reference");
                return false;
            }

            string keyInfoUri = "";
            string signaturePropertiesUri = "";
            string signedPropertiesUri = "";
            List<string> manifestUris = new List<string>();


            foreach (XElement referenceNode in dsReferenceNodes)
            {
                if (referenceNode.Attribute("Id") == null)
                {
                    logger.Log("Error pri overovaní elementov - ds:Reference neobsahuje Id");
                    //Console.WriteLine($"File: {filePath} Error: ds:Reference neobsahuje Id");
                    continue;
                }

                string uriType = referenceNode.Attribute("Type")?.Value;
                if (uriType != null)
                {
                    string uriValue = referenceNode.Attribute("URI")?.Value.Substring(1);

                    if (uriType.Contains("Object"))
                    {
                        keyInfoUri = uriValue;
                    }
                    else if (uriType.Contains("SignatureProperties"))
                    {
                        signaturePropertiesUri = uriValue;
                    }
                    else if (uriType.Contains("SignedProperties"))
                    {
                        signedPropertiesUri = uriValue;
                    }
                    else if (uriType.Contains("Manifest"))
                    {
                        manifestUris.Add(uriValue);
                    }
                }
            }

            XElement KeyInfoElement = xmlDoc.XPathSelectElement("//ds:KeyInfo", namespaceId);
            XElement SignaturePropertiesElement = xmlDoc.XPathSelectElement("//ds:SignatureProperties", namespaceId);
            XElement SignedPropertiesElement = xmlDoc.XPathSelectElement("//xades:SignedProperties", namespaceId);

            if (KeyInfoElement.Attribute("Id")?.Value == null)
            {
                logger.Log("Error pri overovaní elementov - ds:KeyInfo neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje Id");
                return false;
            }

            if (!KeyInfoElement.Attribute("Id").Value.Equals(keyInfoUri))
            {
                logger.Log("Error pri overovaní elementov - ds:Keyinfo nezhoduje sa Id s URI");
                //Console.WriteLine($"File: {filePath} Error: ds:Keyinfo nezhoduje sa Id s URI");
                return false;
            }

            if (SignaturePropertiesElement.Attribute("Id")?.Value == null)
            {
                logger.Log("Error pri overovaní elementov - ds:SignatureProperties neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje Id");
                return false;
            }

            if (!SignaturePropertiesElement.Attribute("Id").Value.Equals(signaturePropertiesUri))
            {
                logger.Log("Error pri overovaní elementov - ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                //Console.WriteLine($"File: {filePath} Error: ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                return false;
            }

            if (SignedPropertiesElement.Attribute("Id")?.Value == null)
            {
                logger.Log("Error pri overovaní elementov - ds:SignedProperties neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:SignedProperties neobsahuje Id");
                return false;
            }

            if (!SignedPropertiesElement.Attribute("Id").Value.Equals(signedPropertiesUri))
            {
                logger.Log("Error pri overovaní elementov - ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                //Console.WriteLine($"File: {filePath} Error: ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                return false;
            }

            // Check attributes of ds:Manifest
            IEnumerable<XElement> elementManifestNodes = xmlDoc.XPathSelectElements("//ds:Manifest", namespaceId);

            bool flag = false;
            foreach (XElement oneManifest in elementManifestNodes)
            {
                foreach (string manifestURI in manifestUris)
                {
                    if (oneManifest.Attribute("Id") == null || !oneManifest.Attribute("Id").Value.Equals(manifestURI))
                        flag = true;
                }
            }

            if (!flag)
            {
                logger.Log("Error pri overovaní elementov - ds:Manifest sa zhoduje sa Id s URI");
                //Console.WriteLine($"File: {filePath} Error: ds:Manifest sa zhoduje sa Id s URI");
                return false;
            }

            // verification of ds:KeyInfo content

            // Check ds:KeyInfo Id
            XElement keyInfoElement = xmlDoc.XPathSelectElement("//ds:KeyInfo", namespaceId);
            if (keyInfoElement?.Attribute("Id")?.Value == null)
            {
                logger.Log("Error pri overovaní elementov - ds:KeyInfo neobsahuje Id");
                //Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje Id");
                return false;
            }

            // Check ds:KeyInfo elements
            XElement x509DataElement = keyInfoElement.XPathSelectElement(".//ds:X509Data", namespaceId);
            if (x509DataElement == null)
            {
                logger.Log("Error pri overovaní elementov - ds:KeyInfo neobsahuje element ds:X509Data");
                //Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje element ds:X509Data");
                return false;
            }

            if (x509DataElement.Elements().Count() < 3)
            {
                logger.Log("Error pri overovaní elementov - Chýbajú podelementy pre ds:X509Data");
                //Console.WriteLine($"File: {filePath} Error: Chýbajú podelementy pre ds:X509Data");
                return false;
            }

            // Check ds:KeyInfo values
            byte[] bytes;
            var certificate = new X509Certificate2();
            string issuerSerialFirst = "";
            string issuerSerialSecond = "";
            string subjectName = "";

            foreach (XElement element in x509DataElement.Elements())
            {
                switch (element.Name.LocalName)
                {
                    case "X509Certificate":
                        bytes = Convert.FromBase64String(element.Value);
                        certificate = new X509Certificate2(bytes);
                        break;
                    case "X509IssuerSerial":
                        XElement firstChild = element.Elements().FirstOrDefault();
                        XElement lastChild = element.Elements().LastOrDefault();
                        issuerSerialFirst = firstChild?.Value ?? "";
                        issuerSerialSecond = lastChild?.Value ?? "";
                        break;
                    case "X509SubjectName":
                        subjectName = element.Value;
                        break;
                }
            }

            BigInteger hex = BigInteger.Parse(certificate.SerialNumber, NumberStyles.AllowHexSpecifier);
            if (!certificate.Subject.Equals(subjectName))
            {
                logger.Log("Error pri overovaní elementov - Hodnota ds:X509SubjectName sa nezhoduje s príslušnou hodnotou v certifikáte");
                //Console.WriteLine( $"File: {filePath} Error: Hodnota ds:X509SubjectName sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }

            if (!certificate.Issuer.Equals(issuerSerialFirst))
            {
                logger.Log("Error pri overovaní elementov - Hodnota ds:X509IssuerName sa nezhoduje s príslušnou hodnotou v certifikáte");
                //Console.WriteLine($"File: {filePath} Error: Hodnota ds:X509IssuerName sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }

            if (!hex.ToString().Equals(issuerSerialSecond))
            {
                logger.Log("Error pri overovaní elementov - Hodnota ds:X509SerialNumber sa nezhoduje s príslušnou hodnotou v certifikát");
                //Console.WriteLine($"Hodnota ds:X509SerialNumber sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }

            // Check ds:SignatureProperties Id
            XElement signaturePropertiesElement = xmlDoc.XPathSelectElement("//ds:SignatureProperties", namespaceId);
            if (signaturePropertiesElement?.Attribute("Id")?.Value == null)
            {
                logger.Log("Error pri overovaní elementov - ds:SignatureProperties neobsahuje Id V2");
                //Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje Id");
                return false;
            }

            // Check ds:SignatureProperties number of elements
            IEnumerable<XElement> signaturePropertiesChildren = signaturePropertiesElement.Elements();
            if (signaturePropertiesChildren.Count() < 2)
            {
                logger.Log("Error pri overovaní elementov - ds:SignatureProperties neobsahuje dva elementy");
                //Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje dva elementy");
                return false;
            }

            // Check ds:SignatureProperties elements
            foreach (XElement element in signaturePropertiesChildren)
            {
                string name = element.Elements().FirstOrDefault()?.Name.LocalName;
                if (name == "ProductInfos" || name == "SignatureVersion")
                {
                    XAttribute targetAttribute = element.Attribute("Target");

                    if (targetAttribute != null)
                    {
                        string tmpTargetValue = targetAttribute.Value.Substring(1);

                        string SignatureValueId = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId)
                            ?.Attribute("Id")?.Value;

                        if (!tmpTargetValue.Equals(SignatureValueId))
                        {
                            logger.Log("Error pri overovaní elementov - Atribut Target v elemente ds:SignatureProperty nie je nastaveny na element ds:Signature");
                            //Console.WriteLine( $"File: {filePath} Error: Atribut Target v elemente ds:SignatureProperty nie je nastaveny na element ds:Signature");
                            return false;
                        }
                    }
                }
            }

            // check ds:Manifest elements
            IEnumerable<XElement> manifestElements = xmlDoc.XPathSelectElements("//ds:Manifest", namespaceId);

            foreach (XElement manifestElement in manifestElements)
            {
                // id atribut
                XAttribute idAttribute = manifestElement.Attribute("Id");
                if (idAttribute == null)
                {
                    logger.Log("Error pri overovaní elementov - ds:Manifest element is missing Id attribute");
                    //Console.WriteLine($"File: {filePath} Error: ds:Manifest element is missing Id attribute");}}
                    return false;
                }

                // ds:Transforms
                XElement transformsElement = manifestElement.Element(namespaceId + "Transforms");
                if (transformsElement == null)
                {
                    logger.Log("Error pri overovaní elementov - ds:Manifest element is missing ds:Transforms element");
                    //Console.WriteLine($"File: {filePath} Error: ds:Manifest element is missing ds:Transforms element");}}
                    return false;
                }

                // ds:DigestMethod
                XElement digestMethodElement = manifestElement.Element(namespaceId + "DigestMethod");
                if (digestMethodElement == null)
                {
                    logger.Log("Error pri overovaní elementov - ds:Manifest element is missing ds:DigestMethod element");
                    //Console.WriteLine($"File: {filePath} Error: ds:Manifest element is missing ds:DigestMethod element");}}
                    return false;
                }

                string[] SUPPORTED_DIGEST_ALGORITHMS =
                {
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    "http://www.w3.org/2001/04/xmldsig-more#sha224",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    "https://www.w3.org/2001/04/xmldsig-more#sha384",
                    "http://www.w3.org/2001/04/xmlenc#sha512"
                };

                string digestAlgorithm = digestMethodElement.Attribute("Algorithm")?.Value;
                if (!SUPPORTED_DIGEST_ALGORITHMS.Contains(digestAlgorithm))
                {
                    logger.Log("Error pri overovaní elementov - Unsupported digest algorithm in ds:DigestMethod");
                    //Console.WriteLine($"File: {filePath} Error: Unsupported digest algorithm in ds:DigestMethod");}}
                    return false;
                }

                // overenie hodnoty Type atribútu voči profilu XAdES_ZEP
                XAttribute typeAttribute = manifestElement.Attribute("Type");
                XElement typeAttributeElement = xmlDoc.XPathSelectElement("//xades:Type", namespaceId);
                if (typeAttribute == null ||
                    !typeAttribute.Value.Equals(typeAttributeElement))
                {
                    logger.Log("Error pri overovaní elementov - Type attribute in ds:Manifest element does not match the expected value");
                    return false;
                }

                // prave jedna referencia
                XElement objectReferenceElement = manifestElement.Elements(namespaceId + "Reference").FirstOrDefault();
                if (objectReferenceElement == null ||
                    objectReferenceElement.Elements(namespaceId + "Object").Count() != 1)
                {
                    logger.Log("Error pri overovaní elementov - ds:Manifest element must contain exactly one reference to ds:Object");
                    //Console.WriteLine($"File: {filePath} Error: ds:Manifest element must contain exactly one reference to ds:Object");}}
                    return false;
                }
            }

            // check ds:Manifest elements references
            return true;
        }

        private bool checkTimestamp(string filePath)
        {
            bool isCertValid = true;
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);
            Org.BouncyCastle.X509.X509Crl timestampCrl = GetTimestampCert();

            var namespaceId = new XmlNamespaceManager(new NameTable());
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceId.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // XPath vyraz na ziskanie certifikatu
            string xpathExpression = "//xades:EncapsulatedTimeStamp";
            XElement x509CertElement = xmlDoc.XPathSelectElement(xpathExpression, namespaceId);

            if (x509CertElement != null)
            {
                // Zakodovany certifikat v Base64
                string base64Cert = x509CertElement.Value;

                // Dekódovanie Base64 reťazca na pole bytov
                byte[] certBytes = Convert.FromBase64String(base64Cert);

                // Vytvorenie X509Certificate objektu z dekódovaných bytov
                Org.BouncyCastle.X509.X509CertificateParser certParser =
                    new Org.BouncyCastle.X509.X509CertificateParser();
                Org.BouncyCastle.X509.X509Certificate x509Certificate =
                    certParser.ReadCertificate(new MemoryStream(certBytes));
                // Overenie platnosti certifikátu časovej pečiatky voči času UtcNow
                isCertValid = x509Certificate.NotBefore <= DateTime.UtcNow &&
                              DateTime.UtcNow <= x509Certificate.NotAfter;
                if (isCertValid)
                {
                    // Overenie platnosti certifikátu časovej pečiatky voči platnému poslednému CRL
                    isCertValid = !timestampCrl.IsRevoked(x509Certificate);
                }
            }
            else
            {
                isCertValid = false;
            }

            return isCertValid;
        }

        private bool checkMessageImprint(string filePath)
        {
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);


            var dsNamespace = new XmlNamespaceManager(new NameTable());
            dsNamespace.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            dsNamespace.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // XPath expression pre získanie timestamp elementu
            string timestampXPath = "//xades:EncapsulatedTimeStamp";
            XElement timestampElement = xmlDoc.XPathSelectElement(timestampXPath, dsNamespace);

            if (timestampElement != null)
            {
                // použijeme existujúcu checkTimestamp funkciu na overenie platnosti
                bool isTimestampValid = checkTimestamp(filePath);

                if (isTimestampValid)
                {
                    // ak aj timestamp aj MessageImprint sú v pohode tak vrátime true
                    Console.WriteLine($"true");
                    return true;
                }
            }

            Console.WriteLine($"false");
            return false;
        }

        private bool checkSignCert(string filePath)
        {
            bool isCertValid = true;
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);
            Org.BouncyCastle.X509.X509Crl signCrl = GetSignCert();

            var namespaceId = new XmlNamespaceManager(new NameTable());
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceId.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // XPath vyraz na ziskanie certifikatu
            string xpathExpression = "//ds:X509Certificate";
            XElement x509CertElement = xmlDoc.XPathSelectElement(xpathExpression, namespaceId);
            string timeString = xmlDoc.XPathSelectElement("//xades:SigningTime", namespaceId).Value;
            DateTime time = DateTime.Parse(timeString);
            if (x509CertElement != null)
            {
                // Zakodovany certifikat v Base64
                string base64Cert = x509CertElement.Value;

                // Dekódovanie Base64 reťazca na pole bytov
                byte[] certBytes = Convert.FromBase64String(base64Cert);

                // Vytvorenie X509Certificate objektu z dekódovaných bytov
                Org.BouncyCastle.X509.X509CertificateParser certParser =
                    new Org.BouncyCastle.X509.X509CertificateParser();
                Org.BouncyCastle.X509.X509Certificate x509Certificate =
                    certParser.ReadCertificate(new MemoryStream(certBytes));
                // Overenie platnosti voči času T
                isCertValid = x509Certificate.NotBefore <= time && time <= x509Certificate.NotAfter;
                if (isCertValid)
                {
                    // Overenie platnosti voči platnému poslednému CRL
                    isCertValid = !signCrl.IsRevoked(x509Certificate);
                }
            }
            else
            {
                isCertValid = false;
            }

            return isCertValid;
        }

        public Org.BouncyCastle.X509.X509Crl GetTimestampCert()
        {
            try
            {
                using (System.Net.WebClient client = new System.Net.WebClient())
                {
                    // Stiahnite CRL zo zadaného URL
                    byte[] crlBytes = client.DownloadData(timestampCrlUrl);
                    if (crlBytes != null)
                    {
                        Org.BouncyCastle.X509.X509CrlParser crlParser = new Org.BouncyCastle.X509.X509CrlParser();
                        Org.BouncyCastle.X509.X509Crl crl = crlParser.ReadCrl(new MemoryStream(crlBytes));
                        return crl;
                    }
                    else
                    {
                        Console.WriteLine("Nepodarilo sa stiahnuť CRL.");
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Chyba pri sťahovaní CRL: {ex.Message}");
                return null;
            }
        }

        public Org.BouncyCastle.X509.X509Crl GetSignCert()
        {
            try
            {
                using (System.Net.WebClient client = new System.Net.WebClient())
                {
                    // Stiahnite CRL zo zadaného URL
                    byte[] crlBytes = client.DownloadData(signCrlUrl);
                    if (crlBytes != null)
                    {
                        Org.BouncyCastle.X509.X509CrlParser crlParser = new Org.BouncyCastle.X509.X509CrlParser();
                        Org.BouncyCastle.X509.X509Crl crl = crlParser.ReadCrl(new MemoryStream(crlBytes));
                        return crl;
                    }
                    else
                    {
                        Console.WriteLine("Nepodarilo sa stiahnuť CRL.");
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Chyba pri sťahovaní CRL: {ex.Message}");
                return null;
            }
        }
    }
}