
# Invoker Burp Extension 🚀

**Invoker** is a Burp Suite extension that automates penetration testing with external tools. It integrates popular programs such as Dosfiner, sqlmap, nuclei, ffuf, tplmap, nikto, and nmap directly into the Burp Suite interface. Pentesters can now launch these tools with just one click, automatically passing data from the currently selected HTTP request.

## 🎯 Key Benefits
- **Time Saving:** No more manual copying URLs, headers, or cookies to CLI tools.
- **Error Reduction:** Automatically generated commands significantly reduce human errors.
- **Bulk Testing:** Generate scripts for multiple endpoints at once.
- **Authenticated Scanning:** Easily reuse session cookies and headers.

## 🛠️ Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/afine-com/Invoker.git
cd Invoker
```

### Step 2: Load into Burp Suite

- Open **Burp Suite**.
- Navigate to the **Extensions** tab.
- Click **Add** and select the file `InvokerExtension.py`.

### Step 3: Configure `InvokerConfig.json`

Edit the `InvokerConfig.json` according to your setup. Each entry in this file defines:

- `tool` – The CLI tool (e.g. dosfiner, sqlmap).
- `name` – Display label in Burp's context menu.
- `template` – Command template using placeholders.

#### ⚠️ Windows Users
Default config is for Linux/macOS. Modify `global_raw_folder` to a writable directory, e.g.:

```json
"global_raw_folder": "C:\pentest\invoker"
```

Specify full paths for executables:

```json
"template": "C:\tools\sqlmap\sqlmap.py -u \"{{URL}}\""
```

## 🔖 Supported Placeholders

| Placeholder         | Description                                               |
|---------------------|-----------------------------------------------------------|
| `{{HOST}}`          | Target hostname or IP                                     |
| `{{URL}}`           | Full request URL                                          |
| `{{PROTOCOL}}`      | Protocol (`http` or `https`)                              |
| `{{PORT}}`          | Port number                                               |
| `{{RAW_PATH}}`      | Path to saved raw request file                            |
| `{{HEADERS[-H]}}`   | All request headers formatted with `-H`                   |
| `{{BODY}}`          | Request body (for POST requests)                          |
| `{{FORCE_SSL}}`     | Adds SSL enforcement flag                                 |
| `{{FFUF_URL}}`      | URL tailored for fuzzing with ffuf                        |
| `{{OUTPUT}}`        | Path for saving the tool’s output                         |
| `{{METHOD_SWITCH}}` | Method flag (`-g` for GET, `-p` for POST)                 |
|---------------------|-----------------------------------------------------------|

## 📌 Example InvokerConfig.json

```json
[
  {"global_raw_folder": "/tmp/{{HOST}}"},
  {
    "name": "dosfiner auto GET/POST",
    "tool": "dosfiner",
    "template": "go run dosfiner.go {{METHOD_SWITCH}} -u \"{{URL}}\" -d \"{{BODY}}\" {{FORCE_SSL}} {{HEADERS[-H]}} -t 999 -proxy \"http://127.0.0.1:8080\""
  },
  {
    "name": "sqlmap auto",
    "tool": "sqlmap",
    "template": "sqlmap -u \"{{URL}}\" {{HEADERS[-H]}} --batch --level=5 --risk=3 --tables"
  }
]
```

## 🚩 Usage Examples

### Single Request (Repeater Tab)

1. Right-click request → **Invoker Extension**.
2. Choose the desired tool (e.g., "dosfiner auto GET/POST").
3. Generated command is copied to clipboard, ready to paste into terminal.

### Bulk Requests (Target Tab)

1. Select multiple requests → Right-click → **Invoker Extension**.
2. Invoker generates a `.sh` script containing commands for each request.
3. Path to `.sh` script is copied to clipboard for quick access.

### Authenticated Requests

1. Select a request with valid authentication (cookies, tokens) → Right-click → **Set as Authenticated Request**.
2. Invoker automatically includes these headers in subsequent commands.

## 🔥 Troubleshooting

- **Windows Configuration:** Ensure `global_raw_folder` points to a writable directory.
- **CLI Path Issues:** Always specify full paths on Windows, e.g., `C:\tools\nuclei.exe`.

