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
        FormData = new FormModel(); 
    }

    public void OnGet()
    { }
    
    [BindProperty]
    public FormModel FormData { get; set; }

    public IActionResult OnPost()
    {
        if (ModelState.IsValid)
        {
            XmlSchemaSet schemaSet = new XmlSchemaSet();
            schemaSet.Add(null, "filmy.xsd"); 
            schemaSet.Compile();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "   " 
            };

            using (XmlWriter xmlWriter = XmlWriter.Create("filmy.xml", settings))
            {
                
                // Create an XML document with the schema reference
                XmlDocument doc = new XmlDocument();
                doc.Schemas.Add(schemaSet);
    
                // Create the root element based on the XSD root element name ("filmy" in this case)
                XmlElement rootElement = doc.CreateElement("filmy"); 
                
                // Create and append "film" elements as needed based on your XSD structure
                XmlElement filmElement = doc.CreateElement("film");
                
                // Create and append "nazov" element
                XmlElement titleElement = doc.CreateElement("nazov");
                titleElement.InnerText = FormData.Title; 
                filmElement.AppendChild(titleElement);

                // Create and append "rok" element
                XmlElement yearElement = doc.CreateElement("rok"); 
                yearElement.InnerText = FormData.Year; 
                filmElement.AppendChild(yearElement);
                
                // Create and append "dlzka_filmu" element
                XmlElement durationElement = doc.CreateElement("dlzka_filmu"); 
                durationElement.InnerText = FormData.Duration; 
                filmElement.AppendChild(durationElement);
                
                rootElement.AppendChild(filmElement);

                doc.AppendChild(rootElement);

                doc.WriteTo(xmlWriter);
            }
            ViewData["PopupMessage"] = ".xml subor bol uspesne vytvoreny";
        }
        return Page();
    }
}