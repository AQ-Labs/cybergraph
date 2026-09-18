# CyberGraph V6 narration

## CyberGraph (0.00s)

Hello, and welcome to CyberGraph. Follow a security finding from its entry point to the code that matters. Inspect the graph, question its evidence, apply a repair, and recheck what remains. This demonstration uses public PyGoat training code, local analysis, and an interactive browser report. No language model is required.

## Install, then choose your repository (23.52s)

Start with Git and Python three point ten or newer. Clone CyberGraph, create and activate a virtual environment, then install the checkout using pip. In your IDE terminal, clone PyGoat and enter its folder. We pin the source for reproducibility. Run doctor to check setup. The dot means this repository. We never install or start the vulnerable application.

## Create the security graph and report (50.60s)

Quickstart initializes configuration, builds the graph, analyzes risks, and writes a report. Python's abstract syntax tree identifies code structure; security rules and call resolution connect the entities. This run finds fourteen issues. Analyze records a history baseline. We then regenerate the visualization with source snippets and a larger node limit. No code is uploaded.

## Where are my results? (77.96s)

Inside your repository, dot cybergraph contains the SQLite database and HTML report. Dot cybergraph dot TOML holds configuration. Quickstart also creates a GitHub Actions workflow: review it before committing. These export commands additionally create graph JSON and SARIF findings. Open report dot HTML in your browser; no web server is needed.

## How to read the graph (103.44s)

The report uses HTML, CSS, JavaScript, and the bundled Cytoscape visualization library. A node represents a code entity; an edge represents a relationship. Blue marks entry points, green marks guards, and red marks sensitive sinks. Dashed regions group security layers. An amber trail highlights the selected attack path. Switch views for architecture, then use search, filters, and node selection to narrow your investigation.

## Follow a risk from entry point to sink (134.00s)

Select the SQL injection path: a Django route, its handler, and a raw database query. Click each node to inspect its role and connections. The path panel reports user-controlled input and no detected sanitizer. Its score prioritizes review, not exploitation probability. Reachability is evidence to investigate, not proof of a successful attack.

## Inspect the exact source-code evidence (158.80s)

Now inspect the source. The handler reads a name and password from the request. Line eight hundred and sixty-four concatenates them into SQL. Line eight hundred and seventy-eight sends the query to objects dot raw. An authentication check is present, but it does not prevent SQL injection. The file and line citations let a developer verify the finding directly.

## Ask a question, then check the citations (183.32s)

Back in the terminal, ask CyberGraph to trace this handler to its SQL sink. Explain returns a confidence level, the connected path, source citations, and repair guidance. This is local graph retrieval, not generated model reasoning. Inspect the cited evidence rather than treating an answer as a security guarantee.

## What does the graph add? (204.92s)

We also ran a small evidence ablation. Across nine seeded questions, two ordinary records contained both endpoint labels eight times; adding path records covered all nine and supplied connected citations. Ranking and limits were unchanged, but path records were longer. This measures evidence availability, not detection accuracy, model quality, or developer productivity.

## Repair, rescan, and review what remains (229.72s)

In our demonstration copy, replace concatenation with SQL placeholders and pass the values separately. Run analyze again, then history. The finding count falls from fourteen to thirteen: one finding fixed, no new findings. Finally, check the working-tree change. REVIEW flags remaining risks and configuration changes. A successful local repair does not make the entire application safe.

## Optional language-model explanations (257.80s)

Language models are optional. Anthropic, OpenAI, or Kimi can phrase the retrieved evidence and reference its citations. Enable a provider only when sharing that context is acceptable. Today's answers remain deterministic and offline. A model's explanation still needs verification; citation instructions do not guarantee accuracy. MCP and SARIF also support IDE and review integrations.

## Thank you (286.00s)

Inspect, question, repair, and recheck. CyberGraph keeps evidence visible and the developer in control. Thank you for watching.