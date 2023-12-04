﻿using Microsoft.AspNetCore.Mvc;
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

                    // Initialize the verification flag
                    bool validationPassed = true;


                    // Verify conditions one by one
                    // Verification of the data envelope - Overenie dátovej obálky
                    if (!DataEnvelope(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie dátovej obálky nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }

                    // Verification XML Signature 
                    if (!Signature(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie XML Signature nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }
                    
                    // Verification Core Validation 
                    if (!CoreValidation(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie Core Validation nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }
                    // verification of other elements
                    if (!CheckElements(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie other elements nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }
                    if (!checkTimestamp(filePath))
                    {
                        validationPassed = false;
                        logger.Log($"Overenie časovej pečiatky nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }
                    //dorobiť
                    /*if(!checkMessageImprint(filePath)) {
                        validationPassed = false;
                        logger.Log($"Overenie Messageimprint nebolo úspešné pre: {filePath}");
                        continue; // Stop verification for this file
                    }*/

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
        private bool DataEnvelope(string filePath)
        {
            // Load XML content from the file
            XDocument xmlDoc = XDocument.Load(filePath);
            // Get the root element
            XElement rootElement = xmlDoc.Root;

            // Check if the root element is not null and contains the required attributes
            return rootElement != null &&
                   rootElement.Attribute(XNamespace.Xmlns + "xzep") != null &&
                   rootElement.Attribute(XNamespace.Xmlns + "ds") != null;
        }

        // Method for verifying the XML Signature
        private bool Signature(string filePath)
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

            if (!SUPPORTED_SIGNATURE_ALGORITHMS.Contains(signatureMethodAlgorithm) ||
                canonicalizationMethodAlgorithm != "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
            {
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
                        return false; // Unsupported transform algorithm found
                    }
                }

                // Check ds:DigestMethod
                string digestAlgorithm = reference.XPathSelectElement("ds:DigestMethod", namespaceId)
                    ?.Attribute("Algorithm")?.Value;
                if (!SUPPORTED_DIGEST_ALGORITHMS.Contains(digestAlgorithm))
                {
                    return false; // Unsupported digest algorithm found
                }
            }

            return true; // All references pass the checks
        }


        private bool CoreValidation(string filePath)
        {
            XDocument xmlDoc = XDocument.Load(filePath);

            var namespaceId = new XmlNamespaceManager(new NameTable());
            namespaceId.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceId.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

            // Check ds:SignedInfo and ds:Manifest
            var signedInfoN = xmlDoc.XPathSelectElement("//ds:SignedInfo", namespaceId);
            var referenceElements = signedInfoN.XPathSelectElements("//ds:Reference", namespaceId);

            // Reference in SignedInfo
            foreach (var reference in referenceElements)
            {
                // Extract ReferenceURI
                string referenceURI = reference.Attribute("URI")?.Value?.Substring(1);

                // Extract digestMethod and digestMethodAlgorithm
                var digestMethod = reference.Element(namespaceId + "DigestMethod");
                // string digestMethodAlgorithm = digestMethod?.Attribute("Algorithm")?.Value;
                string digestMethodAlgorithm = reference.XPathSelectElement("ds:DigestMethod", namespaceId)
                    ?.Attribute("Algorithm")?.Value;
                // Extract dsDigestValue
                string dsDigestValue = reference.XPathSelectElement("ds:DigestValue", namespaceId)
                    ?.Value;

                if (referenceURI.StartsWith("Manifest"))
                {
                    // Console.WriteLine("dsDigestValue " + dsDigestValue );

                    // Get Manifest XML and check DigestValue
                    var manifestElement = xmlDoc.XPathSelectElement($"//ds:Manifest[@Id='{referenceURI}']", namespaceId);
                    if (manifestElement != null)
                    {
                        string manifestXML = manifestElement.ToString();

                        // Use MemoryStream to process the Manifest XML
                        using (MemoryStream sManifest =
                               new MemoryStream(System.Text.Encoding.UTF8.GetBytes(manifestXML)))
                        {
                            // Canonicalization – http://www.w3.org/TR/2001/REC-xml-c14n-20010315
                            XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
                            transform.LoadInput(sManifest);
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
                                // Incorrect hash algorithm
                                return false;

                            // Compute the hash and convert it to Base64
                            byte[] digest = transform.GetDigestedOutput(hash);
                            string result = Convert.ToBase64String(digest);

                            if (!result.Equals(dsDigestValue))
                                // DigestValue does not match with the computation of Manifest
                                return false;
                        }
                    }
                }
            }

            // ds:SignedInfo canonicalization

            // Check if the ds:X509Certificate element exists in the specified XPath
            var x509CertificateElement =
                xmlDoc.XPathSelectElement("//ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaceId);

            if (x509CertificateElement == null)
            {
                // The element ds:X509Data is not present
                return false;
            }

            // Extract the base64-encoded signature certificate from ds:X509Certificate element
            byte[] signatureCertificate = Convert.FromBase64String(x509CertificateElement.Value);

            // Extract the base64-encoded signature value
            byte[] signature =
                Convert.FromBase64String(xmlDoc.XPathSelectElement("//ds:SignatureValue", namespaceId).Value);

            // Extract the ds:SignedInfo element
            var signedInfoElement = xmlDoc.XPathSelectElement("//ds:SignedInfo", namespaceId);

            // Extract the algorithm used for the digital signature in ds:SignedInfo
            string signedInfoSignatureAlg = signedInfoElement.XPathSelectElement("ds:SignatureMethod", namespaceId)
                .Attribute("Algorithm").Value;

            // Apply canonicalization to the ds:SignedInfo element
            XmlDsigC14NTransform canonicalizationTransform = new XmlDsigC14NTransform(false);
            XmlDocument signedInfoDocument = new XmlDocument();
            signedInfoDocument.LoadXml(signedInfoElement.ToString());
            canonicalizationTransform.LoadInput(signedInfoDocument);
            byte[] canonicalizedData = ((MemoryStream)canonicalizationTransform.GetOutput()).ToArray();

            string errMsg = "";

            // Verify the signature using the extracted data and algorithms
            bool verificationResult = this.VerifySignature(signatureCertificate, signature, canonicalizedData,
                signedInfoSignatureAlg, out errMsg);

            if (!verificationResult)
            {
                Console.WriteLine("Error " + errMsg);
                return false;
            }

            // All references passed the validation
            return true;
        }

        private bool VerifySignature(byte[] certificateData, byte[] signature, byte[] data, string signatureAlgorithm,
            out string errorMessage)
        {
            errorMessage = "";

            try
            {
                Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo publicKeyInfo = Org.BouncyCastle.Asn1.X509
                    .X509CertificateStructure
                    .GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(certificateData)).SubjectPublicKeyInfo;
                Org.BouncyCastle.Crypto.AsymmetricKeyParameter publicKey =
                    Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(publicKeyInfo);

                // Determine hash algorithm
                string hashAlgorithm = GetHashAlgorithm(signatureAlgorithm);

                // Determine signature algorithm
                string fullSignatureAlgorithm =
                    GetFullSignatureAlgorithm(publicKeyInfo.AlgorithmID.ObjectID.Id, hashAlgorithm);

                // Hash digest before decryption: Convert.ToBase64String(data));

                Org.BouncyCastle.Crypto.ISigner verifier =
                    Org.BouncyCastle.Security.SignerUtilities.GetSigner(fullSignatureAlgorithm);
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data, 0, data.Length);
                bool result = verifier.VerifySignature(signature);

                // Public Key value:  publicKey.GetHashCode());
                // Hash digest after decryption: Convert.ToBase64String(data)
                // Result result

                if (!result)
                {
                    errorMessage =
                        $"VerifySignature=false: DataB64={Convert.ToBase64String(data)}{Environment.NewLine}SignatureB64={Convert.ToBase64String(signature)}{Environment.NewLine}CertificateDataB64={Convert.ToBase64String(certificateData)}";
                }

                return false;
            }
            catch (Exception ex)
            {
                errorMessage = $"Exception in VerifySignature: {ex}";
                return false;
            }
        }

        private string GetHashAlgorithm(string signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
                case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                    return "sha1";
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                    return "sha256";
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                    return "sha384";
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                    return "sha512";
                default:
                    return string.Empty;
            }
        }

        private string GetFullSignatureAlgorithm(string algorithmId, string hashAlgorithm)
        {
            switch (algorithmId)
            {
                case "1.2.840.10040.4.1": // DSA
                    return $"{hashAlgorithm}withdsa";
                case "1.2.840.113549.1.1.1": // RSA
                    return $"{hashAlgorithm}withrsa";
                default:
                    return string.Empty;
            }
        }
        private bool CheckElements(string filePath)
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
                Console.WriteLine($"File: {filePath} Error: ds:Signature neobsahuje Id");
                return false;
            }
            
            XElement dsSignatureElement = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId);
            if (dsSignatureElement == null)
                return false;
            
            // ds:Signature check namespace xmlns:ds attribute
            XAttribute xmlnsDsAttribute = dsSignatureElement.Attribute(XNamespace.Xmlns + "ds");
            if (xmlnsDsAttribute == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:Signature neobsahuje specifikovany namespace xmlns:ds");
                return false;
            }
            
            // ds:SignatureValue check Id attribute
            string dsSignatureValueId = xmlDoc.XPathSelectElement("//ds:SignatureValue", namespaceId)?.Attribute("Id")?.Value;
            if (dsSignatureValueId == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignatureValue neobsahuje Id");
                return false;
            }
            
            XElement signedInfoElement = xmlDoc.XPathSelectElement("//ds:SignedInfo", namespaceId);
            IEnumerable<XElement> dsReferenceNodes = signedInfoElement.XPathSelectElements(".//ds:Reference", namespaceId);
            

            if (dsReferenceNodes == null || dsReferenceNodes.Count() < 1)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignedInfo neobsahuje ds:Reference");
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
                    Console.WriteLine($"File: {filePath} Error: ds:Reference neobsahuje Id");
                    continue;
                }
               
                string uriType = referenceNode.Attribute("Type")?.Value;
                if (uriType != null)
                {
                    string uriValue = referenceNode.Attribute("URI")?.Value.Substring(1);
                    
                    if (uriType.Contains("Object")) {
                        keyInfoUri = uriValue;
                    }
                    else if (uriType.Contains("SignatureProperties")) {
                        signaturePropertiesUri = uriValue;
                    }
                    else if (uriType.Contains("SignedProperties")) {
                        signedPropertiesUri = uriValue;
                    }
                    else if (uriType.Contains("Manifest")) {
                        manifestUris.Add(uriValue);
                    }
                }
            }
            
            XElement KeyInfoElement = xmlDoc.XPathSelectElement("//ds:KeyInfo", namespaceId);
            XElement SignaturePropertiesElement = xmlDoc.XPathSelectElement("//ds:SignatureProperties", namespaceId);
            XElement SignedPropertiesElement = xmlDoc.XPathSelectElement("//xades:SignedProperties", namespaceId);
            
            if (KeyInfoElement.Attribute("Id")?.Value == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje Id");
                return false;
            }
            if (!KeyInfoElement.Attribute("Id").Value.Equals(keyInfoUri))
            {
                Console.WriteLine($"File: {filePath} Error: ds:Keyinfo nezhoduje sa Id s URI");
                return false;
            }
            
            if (SignaturePropertiesElement.Attribute("Id")?.Value == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje Id");
                return false;
            }
            
            if (!SignaturePropertiesElement.Attribute("Id").Value.Equals(signaturePropertiesUri))
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                return false;
            }
            
            if (SignedPropertiesElement.Attribute("Id")?.Value == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignedProperties neobsahuje Id");
                return false;
            }
            
            if (!SignedPropertiesElement.Attribute("Id").Value.Equals(signedPropertiesUri))
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignaturePropertiesElement nezhoduje sa Id s URI");
                return false;
            }
            
            // Check attributes of ds:Manifest
            IEnumerable<XElement> elementManifestNodes = xmlDoc.XPathSelectElements("//ds:Manifest", namespaceId);
            
            bool flag = false;
            foreach (XElement oneManifest in elementManifestNodes)
            {
                foreach(string manifestURI in manifestUris)
                {
                    if (oneManifest.Attribute("Id") == null || !oneManifest.Attribute("Id").Value.Equals(manifestURI))
                        flag = true;
                }
            }

            if (!flag)
            {
                Console.WriteLine($"File: {filePath} Error: ds:Manifest sa zhoduje sa Id s URI");
                return false;
            }
            
            // verification of ds:KeyInfo content
            
            // Check ds:KeyInfo Id
            XElement keyInfoElement = xmlDoc.XPathSelectElement("//ds:KeyInfo", namespaceId);
            if (keyInfoElement?.Attribute("Id")?.Value == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje Id");
                return false;
            }
            
            // Check ds:KeyInfo elements
            XElement x509DataElement = keyInfoElement.XPathSelectElement(".//ds:X509Data", namespaceId);
            if (x509DataElement == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:KeyInfo neobsahuje element ds:X509Data");
                return false;
            }
            if (x509DataElement.Elements().Count() < 3)
            {
                Console.WriteLine($"File: {filePath} Error: Chýbajú podelementy pre ds:X509Data");
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
                Console.WriteLine($"File: {filePath} Error: Hodnota ds:X509SubjectName sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }
            if (!certificate.Issuer.Equals(issuerSerialFirst))
            {
                Console.WriteLine($"File: {filePath} Error: Hodnota ds:X509IssuerName sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }
            if (!hex.ToString().Equals(issuerSerialSecond))
            {
                Console.WriteLine($"Hodnota ds:X509SerialNumber sa nezhoduje s príslušnou hodnotou v certifikáte");
                return false;
            }
            
            // Check ds:SignatureProperties Id
            XElement signaturePropertiesElement = xmlDoc.XPathSelectElement("//ds:SignatureProperties", namespaceId);
            if (signaturePropertiesElement?.Attribute("Id")?.Value == null)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje Id");
                return false;
            }
            
            // Check ds:SignatureProperties number of elements
            IEnumerable<XElement> signaturePropertiesChildren = signaturePropertiesElement.Elements();
            if (signaturePropertiesChildren.Count() < 2)
            {
                Console.WriteLine($"File: {filePath} Error: ds:SignatureProperties neobsahuje dva elementy");
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
                        
                        string SignatureValueId = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId)?.Attribute("Id")?.Value;
            
                        if (!tmpTargetValue.Equals(SignatureValueId))
                        {
                            Console.WriteLine($"File: {filePath} Error: Atribut Target v elemente ds:SignatureProperty nie je nastaveny na element ds:Signature");
                            return false;
                        }
                    }
                }
            }
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
                Org.BouncyCastle.X509.X509CertificateParser certParser = new Org.BouncyCastle.X509.X509CertificateParser();
                Org.BouncyCastle.X509.X509Certificate x509Certificate = certParser.ReadCertificate(new MemoryStream(certBytes));
                // Overenie platnosti certifikátu časovej pečiatky voči času UtcNow
                isCertValid = x509Certificate.NotBefore <= DateTime.UtcNow && DateTime.UtcNow <= x509Certificate.NotAfter;
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


            //Dorobiť

            return false;
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