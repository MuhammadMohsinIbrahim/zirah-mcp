# Privacy

Zirah is a command-line tool that runs on your machine. It collects no data about you or your
use of it.

## What Zirah does not do

- **No telemetry, analytics or crash reporting.** Zirah never phones home.
- **No account and no cloud service.** There is no Zirah server that receives anything.
- **No upload path.** Reports are printed or written only to the file you name with `-o`.

## When Zirah uses the network

Zirah only connects where you tell it to:

| What you run | What is contacted | What is sent |
|---|---|---|
| `zirah scan server.json` | Nothing | Nothing. A static manifest is read from disk. |
| `zirah scan --allow-exec <command>` | Nothing directly | Nothing. The command runs on your machine; whatever that server itself does is up to the server (see the `--allow-exec` warning). |
| `zirah scan https://…` | The URL you give | Standard MCP requests to list tools, prompts and resources, with a `zirah/<version>` User-Agent. No credentials are sent. |
| `zirah discover` | Nothing | Nothing. It only reads local config files; see [What `zirah discover` reads](README.md#what-zirah-discover-reads). |
| `zirah scan --all` | The remote servers in your configs | The same as a URL scan, for each configured remote server. stdio servers run only with `--allow-exec`. |
| `--llm none` (the default) | Nothing | Nothing. |
| `--llm ollama[:model]` | Your Ollama server (`OLLAMA_HOST`, default `http://localhost:11434`) | The scanned text described below. |
| `--llm openai[:model]` / `--llm anthropic[:model]` | Only the provider you chose | The scanned text described below, with the API key from your environment. |

## What the LLM judge sends

With `--llm`, Zirah sends the provider you chose the text fields of the scanned manifest
(tool, prompt and resource names, titles, descriptions and schemas, and the server
instructions) so it can classify them. It does not send the server's command line,
arguments, environment, headers or your configs.

**Secret values are redacted before anything is sent.** Every value found by the secret rules
(API keys, tokens, private keys, JWTs, passwords in URLs, secret assignments) is replaced with
`[REDACTED:<type>]`, for example `[REDACTED:github-token]`. Nothing of the secret is kept: no
prefix and no length. This happens in the one function every provider uses to send a request,
and if redaction fails for any reason, nothing is sent. The rest of the manifest text is still
sent to the provider you chose, so use `--llm none` (the default) or a local Ollama model for
manifests you would not share with a cloud provider.

API keys for the providers are read only from the environment, sent only to the matching
provider, and never logged or written to reports.

## Local files

- Zirah reads the files you scan, the MCP client configs listed in the README (for
  `discover` and `scan --all`), and your approved-servers list if you have one.
- It writes only the report file you ask for with `-o`.
- Values of environment variables and headers in your configs are never shown, and arguments
  and URLs are redacted with the secret rules before they appear in any output.

Questions or concerns: open an issue, or report a security problem privately as described in
[SECURITY.md](SECURITY.md).
