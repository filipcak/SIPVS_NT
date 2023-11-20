using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Xml.Schema;
using System.Xml.Linq;
using System.Xml.Xsl;
using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Tsp;
using WindowsFormsApp1;
namespace SIPVS_NT.Pages;


public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
    }

    [HttpGet]
    public IActionResult OnGetXmlData()
    {
        try
        {
            XDocument xmlDoc = XDocument.Load("ucastnici.xml");

            return Content(xmlDoc.ToString(), "text/xml");
        }
        catch (Exception ex)
        {
            return BadRequest("Error loading XML: " + ex.Message);
        }
    }

    [HttpGet]
    public IActionResult OnGetXsdData()
    {
        try
        {
            XDocument xmlDoc = XDocument.Load("ucastnici.xsd");

            return Content(xmlDoc.ToString(), "text/xml");
        }
        catch (Exception ex)
        {
            return BadRequest("Error loading XML: " + ex.Message);
        }
    }

    [HttpGet]
    public IActionResult OnGetXslData()
    {
        try
        {
            XDocument xmlDoc = XDocument.Load("transform.xsl");

            return Content(xmlDoc.ToString(), "text/xml");
        }
        catch (Exception ex)
        {
            return BadRequest("Error loading XML: " + ex.Message);
        }
    }
    
    static byte[] ExtractDataFromXmlElement(XmlDocument xmlDoc, string elementName)
    {
        // Your logic to extract data from the specified XML element
        XmlNodeList dataNodes = xmlDoc.GetElementsByTagName(elementName);
        if (dataNodes.Count > 0)
        {
            string innerText = dataNodes[0].InnerText;

            // Convert the string to byte array using a specific encoding (e.g., UTF-8)
            return Encoding.UTF8.GetBytes(innerText);
        }

        // If the element is not found or the extraction logic is more complex, adjust accordingly
        return Array.Empty<byte>();
    }
    
    public IActionResult OnPost()
    {
        if (Request.Form.ContainsKey("generateHtml"))
        {
            // Specify the paths to the XML and XSLT files
            string xmlFilePath = "ucastnici.xml"; // Replace with the actual path
            string xsltFilePath = "transform.xsl"; // Replace with the actual path

            try
            {
                // Load the XML and XSLT files
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlFilePath);

                var xsltDoc = new XslCompiledTransform();
                xsltDoc.Load(xsltFilePath);

                // Perform the transformation
                var resultStream = new MemoryStream();
                xsltDoc.Transform(xmlDoc, null, resultStream);

                // Set the content type and headers for the HTML file
                Response.Headers.Add("Content-Disposition", "attachment; filename=ucastnici_html.html");
                Response.ContentType = "text/html";

                // Return the HTML file as a FileResult
                return File(resultStream.ToArray(), "text/html");
            }
            catch (Exception ex)
            {
                // Handle any exceptions (e.g., file not found)
                return Content("Error: " + ex.Message);
            }
        }
        else if (Request.Form.ContainsKey("addTimestamp"))
        {
            string xmlSignedFilePath = "signed.xml";

            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlSignedFilePath);
                // choosen message imprint from signed.xml
                byte[] signature = ExtractDataFromXmlElement(xmlDoc, "ucastnici");
                
                // Calculate the hash of the extracted data
                Org.BouncyCastle.Crypto.IDigest digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
                digest.BlockUpdate(signature, 0, signature.Length);
                byte[] signatureDigest = new byte[digest.GetDigestSize()];
                int outOff = 0;
                digest.DoFinal(signatureDigest, outOff);

                TimeStampRequestGenerator tsRequestGenerator = new TimeStampRequestGenerator(); // certificate generator
                tsRequestGenerator.SetCertReq(true);
                TimeStampRequest tsRequest = tsRequestGenerator.Generate(TspAlgorithms.Sha256, signatureDigest); // vygenerujeme request

                Timestamp ts = new Timestamp();
                byte[] responseBytes = ts.GetTimestamp(tsRequest.GetEncoded(), "https://test.ditec.sk/TSAServer/tsa.aspx");

                TimeStampResponse tsResponse = new TimeStampResponse(responseBytes);
                
                TimeStampToken timestampToken = tsResponse.TimeStampToken;
                
                // Prapare the XML document with the signature to add the timestamp
                // Create a new element for timestamp information
                XmlElement signatureTimestampElement = xmlDoc.CreateElement("SignatureTimestamp");

                // Add the timestamp data to the element
                XmlElement timeStampElement = xmlDoc.CreateElement("Timestamp");
                timeStampElement.InnerText = timestampToken.TimeStampInfo.GenTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
                XmlElement encapsulatedTimeStamp = xmlDoc.CreateElement("EncapsulatedTimeStamp");
                string base64EncodedToken = Convert.ToBase64String(tsResponse.TimeStampToken.GetEncoded());

                encapsulatedTimeStamp.InnerText = base64EncodedToken;
                XmlElement hashData = xmlDoc.CreateElement("HashData");
                hashData.InnerText = timestampToken.TimeStampInfo.MessageImprintAlgOid;
                
                signatureTimestampElement.AppendChild(timeStampElement);
                signatureTimestampElement.AppendChild(encapsulatedTimeStamp);
                signatureTimestampElement.AppendChild(hashData);

                // Add the timestamp element to the document
                xmlDoc.DocumentElement?.AppendChild(signatureTimestampElement);

                // Save the modified XML document
                xmlDoc.Save("signedTimestamp.xml");
                
                // user to save the XML file
                byte[] xmlBytes = Encoding.UTF8.GetBytes(xmlDoc.OuterXml);

                /*
                // Create a MemoryStream and write the XML content to it
                using (var resultStream = new MemoryStream(xmlBytes))
                {
                    // Set the content type and headers for the XML file
                    Response.Headers.Add("Content-Disposition", "attachment; filename=signedTimestamp.xml");
                    Response.ContentType = "application/xml";
                    // Return the XML file as a FileStreamResult
                    return File(resultStream.ToArray(), "application/xml");
                }
                */
                TempData["result"] = $"Casova peciatka bola pridana\n";
            }
            catch (Exception e)
            {
                return Content("Error: " + e.Message);
            }
        }
        
        if (ModelState.IsValid)
        {
            XmlSchemaSet schema = new XmlSchemaSet();
            schema.Add(null, "ucastnici.xsd");
            XmlSchema schemaRead = XmlSchema.Read(new XmlTextReader("ucastnici.xsd"), null);
            // Get the target namespace from the XmlSchema object
            string targetNamespace = schemaRead.TargetNamespace;
            XmlWriterSettings settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "   "
            };

            using (XmlWriter xmlWriter = XmlWriter.Create("ucastnici.xml", settings))
            {

                // Create an XML document with the schema reference
                XmlDocument doc = new XmlDocument();
                doc.Schemas.Add(schema);

                // Create the root element based on the XSD root element name ("ucastnici" in this case)
                XmlElement rootElement = doc.CreateElement("ucastnici", targetNamespace);


                for (int i = 1; i - 1 < Request.Form.Count / 5; i++)
                {
                    // Create and append "ucastnik" elements as needed based on your XSD structure
                    XmlElement ucastnikElement = doc.CreateElement("ucastnik", targetNamespace);

                    // Create and append "meno" element
                    XmlElement nameElement = doc.CreateElement("meno", targetNamespace);
                    nameElement.InnerText = Request.Form[$"Participants[{i}].Name"];
                    ucastnikElement.AppendChild(nameElement);

                    // Create and append "priezvisko" element
                    XmlElement surnameElement = doc.CreateElement("priezvisko", targetNamespace);
                    surnameElement.InnerText = Request.Form[$"Participants[{i}].Surname"];
                    ucastnikElement.AppendChild(surnameElement);

                    // Create and append "datum_narodenia" element
                    XmlElement dateElement = doc.CreateElement("datum_narodenia", targetNamespace);
                    dateElement.InnerText = Request.Form[$"Participants[{i}].Date"];
                    ucastnikElement.AppendChild(dateElement);

                    // Create and append "vek" element
                    XmlElement ageElement = doc.CreateElement("vek", targetNamespace);
                    ageElement.InnerText = Request.Form[$"Participants[{i}].Age"];
                    ucastnikElement.AppendChild(ageElement);

                    // Create and set the "email" attribute
                    XmlAttribute emailAttribute = doc.CreateAttribute("email");
                    emailAttribute.Value = Request.Form[$"Participants[{i}].Email"];
                    ucastnikElement.Attributes.Append(emailAttribute);

                    rootElement.AppendChild(ucastnikElement);
                }

                doc.AppendChild(rootElement);

                doc.WriteTo(xmlWriter);
                ViewData["PopupMessage"] = ".xml subor bol uspesne vytvoreny";
            }
        }
        return RedirectToPage();
    }

    public IActionResult OnPostUploadXml()
    {
            try
            {
                // Get the XSD file path
                string xsdFilePath = Path.Combine(Directory.GetCurrentDirectory(), "ucastnici.xsd");

                // Validate XML against XSD
                string errorString = "";
                bool isValid = ValidateXmlAgainstXsd(xsdFilePath, ref errorString);

                if (isValid)
                {
                    TempData["result"] = $"XML je validny podla XSD schemy.\n";
                }
                else
                {
                    TempData["result"] = $"XML nie je validny podla XSD schemy.\n{errorString}";
                }
            }
            catch (Exception ex)
            {
                TempData["result"] = $"Chyba: {ex.Message}";
            }
        return RedirectToPage();
    }

    public bool ValidateXmlAgainstXsd(string xsdFilePath, ref string errorString)
    {
        try
        {
            string xmlFilePath = "ucastnici.xml";
            XDocument xDocument = XDocument.Load(xmlFilePath);


            // Load the XSD schema
            XmlSchemaSet schemas = new XmlSchemaSet();
            schemas.Add("http://SIPVS_I_NT_ucastnici_skupina_6", XmlReader.Create(new StreamReader(xsdFilePath)));

            // Load the XML stream with validation settings
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.ValidationType = ValidationType.Schema;
            settings.Schemas = schemas;

            // Validate the XML against the XSD schema
            using (XmlReader reader = XmlReader.Create(xmlFilePath, settings))
            {
                while (reader.Read())
                {
                }
            }

            // If validation succeeds, return true
            return true;
        }
        catch (XmlSchemaValidationException ex)
        {
            // Validation failed, print the validation error if needed
            // Console.WriteLine($"Validation error: {ex.Message}");
            errorString = ex.Message;
            return false;
        }
        catch (Exception ex)
        {
            // Other exceptions, handle them as needed
            // Console.WriteLine($"Error: {ex.Message}");
            errorString = ex.Message;
            return false;
        }
    }

}