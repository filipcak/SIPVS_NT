using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Xml.Schema;

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
    
    public IActionResult OnPost()
    {
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


                for (int i = 1; i-1 < Request.Form.Count / 5; i++)
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
        
        return Page();
    }

    public IActionResult OnPostUploadXml(IFormFile xmlFile)
    {
        if (xmlFile != null && xmlFile.Length > 0)
        {
            try
            {
                // Get the XSD file path
                string xsdFilePath = Path.Combine(Directory.GetCurrentDirectory(), "ucastnici.xsd");

                // Validate XML against XSD
                string errorString = "";
                bool isValid = ValidateXmlAgainstXsd(xmlFile.OpenReadStream(), xsdFilePath, ref errorString);

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
        }
        else
        {
            TempData["result"] = "Vyberte platny XML subor.";
        }

        return Page();
    }

    public bool ValidateXmlAgainstXsd(Stream xmlStream, string xsdFilePath, ref string errorString)
    {
        try
        {
            // Load the XSD schema
            XmlSchemaSet schemas = new XmlSchemaSet();
            schemas.Add("SIPVS_I_NT_ucastnici_skupina_6", XmlReader.Create(new StreamReader(xsdFilePath)));

            // Load the XML stream with validation settings
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.ValidationType = ValidationType.Schema;
            settings.Schemas = schemas;

            // Validate the XML against the XSD schema
            using (XmlReader reader = XmlReader.Create(xmlStream, settings))
            {
                while (reader.Read()) { }
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
        finally
        {
            // Close the XML stream
            xmlStream.Close();
        }
    }
}