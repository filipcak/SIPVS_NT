using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;


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
            string signatureMethodAlgorithm = xmlDoc.XPathSelectElement("//ds:SignedInfo/ds:SignatureMethod", namespaceId)?.Attribute("Algorithm")?.Value;
            string canonicalizationMethodAlgorithm = xmlDoc.XPathSelectElement("//ds:SignedInfo/ds:CanonicalizationMethod", namespaceId)?.Attribute("Algorithm")?.Value;

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
    }
}