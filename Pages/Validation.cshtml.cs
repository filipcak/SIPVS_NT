using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using System.Security.Cryptography.Xml;
using System.Text;


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
            
            string dsSignatureId = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId)?.Attribute("Id")?.Value;
            if (dsSignatureId == null)
                return false;
            
            XElement dsSignatureElement = xmlDoc.XPathSelectElement("//ds:Signature", namespaceId);
            if (dsSignatureElement == null)
                return false;
            
            XAttribute xmlnsDsAttribute = dsSignatureElement.Attribute(XNamespace.Xmlns + "ds");
            Console.WriteLine($"Error logging: {xmlnsDsAttribute}");
            if ( xmlnsDsAttribute == null)
                return false;
 
            string dsSignatureValueId = xmlDoc.XPathSelectElement("//ds:SignatureValue", namespaceId)?.Attribute("Id")?.Value;
            if (dsSignatureValueId == null)
                return false;
            
            string KeyInfo = xmlDoc.XPathSelectElement("//ds:KeyInfo", namespaceId)?.Attribute("Id")?.Value;
            if (KeyInfo == null)
                return false;
            
            string SignatureProperties = xmlDoc.XPathSelectElement("//ds:SignatureProperties", namespaceId)?.Attribute("Id")?.Value;
            if (SignatureProperties == null)
                return false;
            
            string SignedProperties = xmlDoc.XPathSelectElement("//xades:SignedProperties", namespaceId)?.Attribute("Id")?.Value;
            if (SignedProperties == null)
                return false;
            
            return true;
        }
    }
}