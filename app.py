#!/usr/bin/env python3
"""Lab Recon Gradio interface."""

from __future__ import annotations

import html
import sys

import gradio as gr

from engine import AUTH_PHRASE, Assessment, assess, explain_findings, recommendations, to_markdown, write_reports

MODULES = ["DNS", "HTTP headers", "TLS certificate", "Common ports"]

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@500;600&family=Fira+Sans:wght@400;500;600;700&display=swap');

:root {
  --lr-navy: #1E3A5F;
  --lr-ink: #0F172A;
  --lr-muted: #475569;
  --lr-line: #E4E7EB;
  --lr-surface: #FFFFFF;
  --lr-canvas: #F8FAFC;
  --lr-green: #047857;
  --lr-amber: #B45309;
  --lr-red: #B91C1C;
}

html, body, body.dark, .dark, body > div, gradio-app, .gradio-container {
  background: var(--lr-canvas) !important;
  color: var(--lr-ink) !important;
  font-family: "Fira Sans", sans-serif !important;
}

html, body {
  min-height: 100%;
  color-scheme: light;
}

.tabs, .tabitem, textarea, .table-wrap, table, th, td, .cell-wrap, .dataframe {
  background-color: #FFFFFF;
  color: #0F172A;
}

.dark textarea, .dark table, .dark th, .dark td,
.dark .tabitem, .dark .prose, .dark .markdown, .dark .table-wrap {
  background-color: #FFFFFF !important;
  color: #0F172A !important;
}

.gradio-container {
  max-width: 1120px !important;
  padding-top: 24px !important;
}

.prose code, .markdown code, code {
  background: #F1F5F9 !important;
  color: #1E3A5F !important;
  border-radius: 4px;
  padding: 0.05em 0.35em;
}

.lr-header h1 {
  margin: 0;
  font-family: "Fira Code", monospace;
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.03em;
  color: var(--lr-navy);
}

.lr-header p {
  margin: 8px 0 0;
  max-width: 68ch;
  color: var(--lr-muted);
  font-size: 16px;
  line-height: 1.6;
}

.lr-section {
  margin: 8px 12px 0;
  font-size: 18px;
  color: var(--lr-navy);
}

.lr-panel {
  background: var(--lr-surface);
  border: 1px solid var(--lr-line);
  border-radius: 12px;
  padding: 8px 4px 12px;
}

button.lg {
  min-height: 48px !important;
  font-weight: 600 !important;
  border-radius: 8px !important;
  transition: background-color 200ms ease !important;
}

button.primary {
  background: var(--lr-navy) !important;
  color: #FFFFFF !important;
}

button.primary:hover {
  background: #16304F !important;
}

button.secondary {
  min-height: 48px !important;
  border-radius: 8px !important;
  font-weight: 600 !important;
  background: #FFFFFF !important;
  color: var(--lr-navy) !important;
  border: 1px solid #CBD5E1 !important;
}

footer {
  display: none !important;
}

button:focus-visible {
  outline: 3px solid #2563EB !important;
  outline-offset: 2px !important;
}

.lr-steps {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 20px 0 8px;
  padding: 0;
  list-style: none;
}

.lr-steps li {
  background: var(--lr-surface);
  border: 1px solid var(--lr-line);
  border-radius: 12px;
  padding: 14px 16px;
  min-height: 96px;
}

.lr-steps strong {
  display: block;
  color: var(--lr-navy);
  font-size: 15px;
}

.lr-steps span {
  display: block;
  margin-top: 6px;
  color: var(--lr-muted);
  font-size: 14px;
  line-height: 1.45;
}

.lr-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  margin: 12px 0 4px;
  padding: 0;
  list-style: none;
  color: var(--lr-ink);
  font-size: 14px;
}

.lr-legend li {
  display: flex;
  align-items: center;
  gap: 8px;
}

.tag {
  display: inline-block;
  min-width: 64px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 700;
  text-align: center;
}

.tag.fail { background: #FEF2F2; color: #B91C1C; }
.tag.review { background: #FFFBEB; color: #92400E; }
.tag.info { background: #ECFDF5; color: #047857; }

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.metric {
  background: var(--lr-surface);
  border: 1px solid var(--lr-line);
  border-radius: 12px;
  padding: 16px;
  min-height: 96px;
}

.metric .k {
  display: block;
  color: var(--lr-muted);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}

.metric .v {
  display: block;
  margin-top: 6px;
  font-family: "Fira Code", monospace;
  font-size: 28px;
  font-weight: 600;
  color: var(--lr-navy);
}

.metric .s {
  display: block;
  margin-top: 4px;
  color: var(--lr-ink);
  font-size: 14px;
  line-height: 1.4;
}

.status-line {
  margin: 0 0 12px;
  padding: 12px 14px;
  border-radius: 8px;
  background: #ECFDF5;
  color: var(--lr-green);
  font-weight: 600;
}

.status-line.attention {
  background: #FFFBEB;
  color: var(--lr-amber);
}

.status-line.problem {
  background: #FEF2F2;
  color: var(--lr-red);
}

@media (max-width: 800px) {
  .metrics, .lr-steps { grid-template-columns: 1fr 1fr; }
}

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""


def _empty_metrics() -> str:
    return _metrics("—", "Waiting", "—", "Not run", "—", "Not run", "—", "Not run")


def _metrics(
    review: str,
    review_note: str,
    ports: str,
    ports_note: str,
    headers: str,
    headers_note: str,
    cert: str,
    cert_note: str,
) -> str:
    cards = (
        ("To review", review, review_note),
        ("Open ports", ports, ports_note),
        ("Headers present", headers, headers_note),
        ("Certificate", cert, cert_note),
    )
    body = []
    for label, value, note in cards:
        body.append(
            f'<article class="metric"><span class="k">{label}</span>'
            f'<span class="v">{value}</span><span class="s">{note}</span></article>'
        )
    return '<section class="metrics">' + "".join(body) + "</section>"


def _status(result: Assessment) -> str:
    note = result.coyote or {}
    if note.get("text"):
        extra = " CoyoteGPT added a note on the Summary tab."
    elif note.get("error"):
        extra = " CoyoteGPT did not answer. The checks are still complete."
    else:
        extra = ""
    if result.review_count == 0:
        return f'<p class="status-line">Complete. No review items for the selected checks.{extra}</p>'
    noun = "item needs" if result.review_count == 1 else "items need"
    return (
        f'<p class="status-line attention">Complete. {result.review_count} {noun} '
        f"review. Details are in Findings and the report.{extra}</p>"
    )


def _findings_rows(result: Assessment) -> list[list[str]]:
    if not result.findings:
        return [["Info", "Assessment", "No findings", "The selected checks did not raise a finding."]]
    return [[item.severity, item.area, item.title, item.detail] for item in result.findings]


def _summary_md(result: Assessment) -> str:
    lines = [
        f"**{result.engagement}**",
        "",
        f"Operator {result.operator} assessed **{result.host}** on {result.generated_at}.",
        "",
        result.notes or "No operator notes were added.",
    ]
    note = result.coyote or {}
    if note.get("text"):
        lines.extend(["", f"**CoyoteGPT ({note.get('model')})**", "", note["text"]])
    elif note.get("error"):
        lines.extend(["", "**CoyoteGPT**", "", note["error"]])
    return "\n".join(lines)


def _next_steps_md(result: Assessment) -> str:
    lines = ["**Next steps**", ""]
    for index, step in enumerate(recommendations(result), start=1):
        lines.append(f"{index}. {step}")
    return "\n".join(lines)


def run_assessment(operator, engagement, confirmation, target, modules, notes, use_coyote, progress=gr.Progress()):
    try:
        progress(0.05, desc="Checking the form")
        result = assess(
            operator,
            engagement,
            confirmation,
            target,
            modules,
            notes,
            on_step=lambda fraction, desc: progress(fraction, desc=desc),
        )
    except ValueError as exc:
        message = f'<p class="status-line problem">{html.escape(str(exc))}</p>'
        return (
            message,
            _empty_metrics(),
            _summary_md_error(str(exc)),
            [["Review", "Form", "Check not run", str(exc)]],
            [],
            [],
            [],
            [],
            "The report was not written. Fix the message above, then run the assessment again.",
            "",
            None,
            None,
        )

    if use_coyote:
        progress(0.94, desc="Asking CoyoteGPT")
        result.coyote = explain_findings(result)
    headers = result.http.get("headers") or []
    present = sum(1 for row in headers if row["state"] == "present")
    days = result.tls.get("days_remaining") if result.tls.get("ok") else None
    cert_value = "—" if days is None else str(days)
    cert_note = "days remaining" if days is not None else html.escape((result.tls.get("error") or "not checked")[:42])
    header_value = f"{present}/{len(headers)}" if headers else "—"
    markdown_path, json_path = write_reports(result)
    cookies = result.http.get("cookies") or []
    progress(1, desc="Report ready")
    return (
        _status(result),
        _metrics(
            str(result.review_count),
            "review or fail",
            str(result.open_ports),
            f"of {len(result.ports)} checked" if result.ports else "ports not checked",
            header_value,
            "security headers",
            cert_value,
            cert_note,
        ),
        _summary_md(result),
        _findings_rows(result),
        [[row["record"], row["result"]] for row in result.dns],
        [[row["header"], row["state"], row["value"]] for row in headers],
        [[row["port"], row["service"], row["state"]] for row in result.ports],
        [[row["cookie"], row["secure"], row["httponly"]] for row in cookies],
        _next_steps_md(result),
        to_markdown(result),
        markdown_path,
        json_path,
    )


def _summary_md_error(message: str) -> str:
    return f"**The assessment did not run.**\n\n{message}"


def build_theme():
    return gr.themes.Base(
        primary_hue=gr.themes.colors.slate,
        secondary_hue=gr.themes.colors.blue,
        neutral_hue=gr.themes.colors.slate,
        font=gr.themes.GoogleFont("Fira Sans"),
        font_mono=gr.themes.GoogleFont("Fira Code"),
    ).set(
        body_background_fill="#F8FAFC",
        body_background_fill_dark="#F8FAFC",
        body_text_color="#0F172A",
        body_text_color_dark="#0F172A",
        body_text_color_subdued="#475569",
        body_text_color_subdued_dark="#475569",
        background_fill_primary="#FFFFFF",
        background_fill_primary_dark="#FFFFFF",
        background_fill_secondary="#F8FAFC",
        background_fill_secondary_dark="#F8FAFC",
        border_color_primary="#E4E7EB",
        border_color_primary_dark="#E4E7EB",
        block_background_fill="#FFFFFF",
        block_background_fill_dark="#FFFFFF",
        block_border_color="#E4E7EB",
        block_border_color_dark="#E4E7EB",
        block_label_text_color="#0F172A",
        block_label_text_color_dark="#0F172A",
        block_label_text_weight="600",
        block_info_text_color="#475569",
        block_info_text_color_dark="#475569",
        block_title_text_color="#0F172A",
        block_title_text_color_dark="#0F172A",
        panel_background_fill="#FFFFFF",
        panel_background_fill_dark="#FFFFFF",
        panel_border_color="#E4E7EB",
        panel_border_color_dark="#E4E7EB",
        input_background_fill="#FFFFFF",
        input_background_fill_dark="#FFFFFF",
        input_border_color="#E4E7EB",
        input_border_color_dark="#E4E7EB",
        code_background_fill="#F1F5F9",
        code_background_fill_dark="#F1F5F9",
        table_border_color="#E4E7EB",
        table_border_color_dark="#E4E7EB",
        table_even_background_fill="#FFFFFF",
        table_even_background_fill_dark="#FFFFFF",
        table_odd_background_fill="#F8FAFC",
        table_odd_background_fill_dark="#F8FAFC",
        table_row_focus="#EFF6FF",
        table_row_focus_dark="#EFF6FF",
        block_label_background_fill="#FFFFFF",
        block_label_background_fill_dark="#FFFFFF",
        block_title_background_fill="#FFFFFF",
        block_title_background_fill_dark="#FFFFFF",
        input_background_fill_focus="#FFFFFF",
        input_background_fill_focus_dark="#FFFFFF",
        input_background_fill_hover="#FFFFFF",
        input_background_fill_hover_dark="#FFFFFF",
        input_placeholder_color="#475569",
        input_placeholder_color_dark="#475569",
        table_text_color="#0F172A",
        table_text_color_dark="#0F172A",
        button_primary_background_fill="#1E3A5F",
        button_primary_background_fill_dark="#1E3A5F",
        button_primary_text_color="#FFFFFF",
        button_primary_text_color_dark="#FFFFFF",
        button_primary_background_fill_hover="#16304F",
        button_primary_background_fill_hover_dark="#16304F",
        button_secondary_background_fill="#FFFFFF",
        button_secondary_background_fill_dark="#FFFFFF",
        button_secondary_text_color="#1E3A5F",
        button_secondary_text_color_dark="#1E3A5F",
        button_secondary_border_color="#CBD5E1",
        button_secondary_border_color_dark="#CBD5E1",
    )


READY = '<p class="status-line">Ready. Fill in the engagement, then run the assessment.</p>'
SUMMARY_PLACEHOLDER = "The summary appears here after a run. Start with the host from your lab sheet."
STEPS_PLACEHOLDER = "Next steps appear here after a successful run."


def clear_form():
    return (
        "",
        "Class lab",
        "",
        "",
        MODULES,
        "",
        True,
        READY,
        _empty_metrics(),
        SUMMARY_PLACEHOLDER,
        [],
        [],
        [],
        [],
        [],
        STEPS_PLACEHOLDER,
        "",
        None,
        None,
    )


def build_demo():
    with gr.Blocks(title="Lab Recon") as demo:
        gr.HTML(
            """
            <header class="lr-header">
              <h1>Lab Recon</h1>
              <p>An authorized assessment worksheet. Record DNS, response headers, the certificate, and four common ports, then download a report for the lab write-up.</p>
            </header>
            <ol class="lr-steps">
              <li><strong>1. Name the work</strong><span>Operator, engagement, and the host you are allowed to test.</span></li>
              <li><strong>2. Confirm access</strong><span>Type the authorization phrase exactly. The check will not run without it.</span></li>
              <li><strong>3. Run the checks</strong><span>DNS, headers, the certificate, and ports 22, 80, 443, and 8080.</span></li>
              <li><strong>4. Download the report</strong><span>Markdown for the write-up. JSON keeps the same evidence.</span></li>
            </ol>
            """
        )
        with gr.Row():
            with gr.Column(scale=4, elem_classes=["lr-panel"]):
                gr.HTML('<h2 class="lr-section">Engagement</h2>')
                operator = gr.Textbox(label="Operator name", info="Printed at the top of the report.")
                engagement = gr.Textbox(
                    label="Engagement name",
                    info="Use the lab or assignment title.",
                    value="Class lab",
                )
                target = gr.Textbox(
                    label="Host",
                    info="Hostname or IP you are allowed to test. A URL is accepted; the path is ignored.",
                )
                confirmation = gr.Textbox(
                    label="Authorization",
                    info=f"Type exactly: {AUTH_PHRASE}",
                )
                modules = gr.CheckboxGroup(
                    label="Checks",
                    choices=MODULES,
                    value=MODULES,
                    info="Leave all four selected for a full worksheet.",
                )
                notes = gr.Textbox(
                    label="Notes",
                    lines=3,
                    info="Optional context, such as which lab machine this is.",
                )
                use_coyote = gr.Checkbox(
                    label="Explain the findings with CoyoteGPT",
                    value=True,
                    info="Sends the finished findings to the local class model and adds its note to the report.",
                )
                with gr.Row():
                    run = gr.Button("Run assessment", variant="primary", elem_classes=["primary"])
                    clear = gr.Button("Clear", variant="secondary", elem_classes=["secondary"])
            with gr.Column(scale=7, elem_classes=["lr-panel"]):
                status = gr.HTML(value=READY)
                metrics = gr.HTML(value=_empty_metrics())
                gr.HTML(
                    """
                    <ul class="lr-legend">
                      <li><span class="tag fail">Fail</span> A hard condition failed, such as an expired certificate.</li>
                      <li><span class="tag review">Review</span> Confirm this before you turn the worksheet in.</li>
                      <li><span class="tag info">Info</span> Recorded. No action required.</li>
                    </ul>
                    """
                )
                with gr.Tabs():
                    with gr.Tab("Summary"):
                        summary = gr.Markdown(SUMMARY_PLACEHOLDER)
                        next_steps = gr.Markdown(STEPS_PLACEHOLDER)
                    with gr.Tab("Findings"):
                        findings = gr.Dataframe(
                            headers=["Severity", "Area", "Finding", "Detail"],
                            datatype=["str", "str", "str", "str"],
                            row_count=(1, "dynamic"),
                            interactive=False,
                            label="Findings",
                        )
                    with gr.Tab("Evidence"):
                        dns = gr.Dataframe(
                            headers=["record", "result"],
                            label="DNS",
                            interactive=False,
                        )
                        http = gr.Dataframe(
                            headers=["header", "state", "value"],
                            label="HTTP security headers",
                            interactive=False,
                        )
                        cookies = gr.Dataframe(
                            headers=["cookie", "secure", "httponly"],
                            label="Cookies",
                            interactive=False,
                        )
                        ports = gr.Dataframe(
                            headers=["port", "service", "state"],
                            label="Ports 22, 80, 443, 8080",
                            interactive=False,
                        )
                    with gr.Tab("Report"):
                        gr.Markdown(
                            "After a successful run, read the preview, then download both files. "
                            "Markdown is the write-up. JSON is the same evidence in a structured file. "
                            "Copies are also saved in the `reports` folder next to the app."
                        )
                        preview = gr.Textbox(label="Report preview", lines=16, interactive=False)
                        with gr.Row():
                            markdown_file = gr.File(label="Markdown report")
                            json_file = gr.File(label="JSON report")
                    with gr.Tab("Method"):
                        gr.Markdown(
                            """
**What each check does**

- **DNS** asks for the A and AAAA records of the host.
- **HTTP headers** makes one request and records six security headers, the server name, and cookie flags.
- **TLS certificate** completes one handshake on port 443 and records the subject, issuer, protocol, and days remaining.
- **Common ports** connects to 22, 80, 443, and 8080, waiting half a second between checks.
- **CoyoteGPT** reads those findings and writes a short report note. The class API model is `classroom-tutor-a` at coyotegpt.ngrok.app.

**What this worksheet does not do**

It does not guess passwords, exploit services, or scan the full port range. Run it only on a host you are authorized to test.
                            """
                        )
        outputs = [status, metrics, summary, findings, dns, http, ports, cookies, next_steps, preview, markdown_file, json_file]
        run.click(
            run_assessment,
            inputs=[operator, engagement, confirmation, target, modules, notes, use_coyote],
            outputs=outputs,
        )
        clear.click(
            clear_form,
            outputs=[operator, engagement, target, confirmation, modules, notes, use_coyote, *outputs],
        )
    return demo


HEAD = """
<script>
(function () {
  function keepLight() {
    document.documentElement.classList.remove("dark");
    if (document.body) document.body.classList.remove("dark");
    document.documentElement.style.colorScheme = "light";
  }
  keepLight();
  document.addEventListener("DOMContentLoaded", keepLight);
  const observer = new MutationObserver(keepLight);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  const watchBody = new MutationObserver(function () {
    if (!document.body) return;
    observer.observe(document.body, { attributes: true, attributeFilter: ["class"] });
    watchBody.disconnect();
    keepLight();
  });
  watchBody.observe(document.documentElement, { childList: true });
})();
</script>
"""


def main() -> None:
    build_demo().launch(theme=build_theme(), css=CSS, head=HEAD, share="--share" in sys.argv)


if __name__ == "__main__":
    main()
