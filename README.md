</details>

---

<details>
<summary>Click to expand sample README.md</summary>

```markdown
# Burp Invoker Extension

**Burp Invoker** is a Jython-based Burp Suite extension that generates CLI commands for various security tools (like `dosfiner`, `sqlmap`, `ffuf`, `nuclei`, etc.) directly from requests in Burp. It supports:

- Generating commands from Repeater requests  
- Capturing headers, body, method, proxy settings  
- Copying the final command to the clipboard or writing multi-request commands to a file  
- Automatic logic for GET vs POST, SSL flags, raw request saving, etc.

## Installation

1. Download the Jython standalone JAR (e.g. `jython-standalone-2.7.2.jar`).
2. In Burp Suite → Extender → Options → Add the Jython JAR as your Python Environment.
3. In Burp → Extender → Extensions → Add → Python: select `InvokerExtension.py`.
4. Check Burp Extender logs for successful load.

## Usage

- In **Repeater**, right-click → **Invoker** → choose a tool (like `dosfiner` or `sqlmap`).  
- The extension auto-detects request method, URL, headers, body.  
- A command string is generated and copied to your clipboard (and shown in a popup).  
- For multiple selected requests (in Target), it can produce a `.sh` file with lines for each request, or copy the path to the clipboard.

### Example: Generating dosfiner commands
1. Right-click on a request in Repeater → *"Invoker → Doser auto GET/POST"*.  
2. A command like `go run dosfiner.go -g -u "http://example.com" -t 100 ...` is created.  
3. It's copied to clipboard, or for multiple requests, they’re aggregated into a `.sh`.

## Example Tools Supported

- **dosfiner**: concurrency-based stress tool (Go)  
- **sqlmap**: automated SQL injection tester (Python)  
- **ffuf**: fuzzing file paths or parameters (Go)  
- **nuclei**: template-based vulnerability scanner (Go)  
- **tplmap**: server-side template injection tester (Python)  

*(You can also add your own tools by editing InvokerConfig.json.)*

## Configuration (InvokerConfig.json)
- The extension reads a local JSON file specifying each tool’s name, "template" placeholders, etc.
- For instance:
  ```json
  [
    {
      "tool": "dosfiner",
      "name": "Doser raw",
      "template": "go run dosfiner.go -r \"{{RAW_PATH}}\" -t 9999"
    },
    {
      "tool": "sqlmap",
      "name": "sqlmap basic",
      "template": "sqlmap -u \"{{URL}}\" --force-ssl --batch"
    }
  ]
