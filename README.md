# Lab Recon

An authorized assessment worksheet. Enter the engagement, run the checks, and download a Markdown or JSON report.

The page walks through four steps: name the engagement, type the authorization phrase, run the checks, and download the report. It shows a status line, four summary figures, a severity key, and tabs for the summary, findings, evidence, the report, and the method. It checks DNS, HTTP security headers, cookies, the TLS certificate, and ports 22, 80, 443, and 8080. Each successful run writes Markdown and JSON under `reports/`. With **Explain the findings with CoyoteGPT** selected, the finished findings are sent to the local class model at `https://coyotegpt.ngrok.app/api/v1` and the reply is added to the summary and the report. The model id on that API is `classroom-tutor-a`. Set `COYOTE_API_KEY` if the key is not already available on this machine. It does not exploit services, guess passwords, or scan every port.

## Download and set up

```bash
curl -fsSL https://raw.githubusercontent.com/ji9-alt/lab-recon/main/setup.sh | bash
cd lab-recon
source .venv/bin/activate
python app.py
```

If you already have the folder, run `./setup.sh` inside it. The script installs the dependencies. It does not ask for or save an API key.

For the CoyoteGPT note, set `COYOTE_API_KEY` in the terminal that starts the app, then run `python app.py`. Keep that key in your shell only. Do not put it in a file in this project.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open the local URL Gradio prints.

Before the checks run, type this phrase exactly:

```text
I am authorized to test this host
```

Then enter a hostname or IP, such as a class lab machine.

## Shareable link

The class submission is the public Gradio link:

```bash
python app.py --share
```

Gradio prints a `https://....gradio.live` URL. That is the link to turn in.

Use the tool only on hosts you have permission to test.
