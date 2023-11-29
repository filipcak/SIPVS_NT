using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;

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
                    // pridanie dalsieho overenia
                    
                    // If all conditions passed, log successful validation
                    if (validationPassed)
                    {
                        logger.Log($"Súbor bol úspešne validovaný: {fileName}");
                    }
                }

                // Logic or return a response if needed
                return Content("<script>alert('Process finished'); window.location.href='/Validation'</script>", "text/html");
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
    }
}
