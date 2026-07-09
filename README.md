# Header Fusion

**Header Fusion** is a Burp Suite extension written in Kotlin using the modern Montoya API. It is designed to automate access control and privilege escalation fuzzing by testing permuted combinations of predefined authorization headers.

Manually swapping headers between User A and User B to test for IDOR or broken object-level authorization is slow and repetitive. Header Fusion solves this by dynamically generating all combinations of configured target headers and sending them sequentially, monitoring for changes in status codes and response sizes.

---

## Features

- **Montoya API Integration**: Bypasses legacy Extender constraints to support HTTP/1.1, HTTP/2, and HTTP/3 requests natively.
- **Draggable Split-Pane UI**: Displays the header configurations on top and live fuzzing results at the bottom within a draggable split pane.
- **Live Logs View**: Tracks every sent request in real-time, showing:
  - Request Number (`#`)
  - HTTP Method
  - Path & Parameters
  - Status Code
  - Response Body Size (in bytes)
  - Response Header Size (in bytes)
- **Inline Cell Editing**: Fast double-click interface to add, edit, or rename header keys and values directly in the tables.
- **Batch Header Importing**: Paste raw HTTP headers in bulk (e.g. copied from another Burp request) to populate User A or User B instantly.
- **Unified JSON Config**: Save and load complete user profiles concurrently to a single JSON configuration file.
- **Persistent State**: Automatically saves settings natively inside your active Burp Suite project file so configurations persist across restarts.

---

## How to Build the Project

### Prerequisites
- Java Development Kit (JDK) 21
- Gradle (handled via Gradle wrapper)

### Build Command
Compile the extension into a standalone JAR file:
```bash
./gradlew jar
```
The output artifact will be saved to:
`build/libs/header-fusion-2.1.jar`

---

## Installation & Usage

1. Load the compiled `header-fusion-2.1.jar` into Burp Suite under **Extensions > Installed > Add**.
2. Go to the new **Header Fusion** tab.
3. Configure the header values:
   - Click **Add headers** to paste raw headers in bulk.
   - Double-click table cells to edit target keys (e.g. `Authorization`, `X-Workspace-Id`, `Cookie`) and values for both User A and User B.
4. Locate any request you want to fuzz (e.g. in **Proxy History** or **Repeater**).
5. Right-click the request and choose **Fuzz**.
6. View the live testing logs in the draggable panel below the tables.

---

## Authors
- [Bineeg K Biju](https://www.linkedin.com/in/bineeg/)
- [Amal Thamban](https://www.linkedin.com/in/amalthamban/)
