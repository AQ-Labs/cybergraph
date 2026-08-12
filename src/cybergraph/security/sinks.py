"""Sensitive-sink registry.

Replaces substring keyword matching, which fired on ``drawChart`` for ``raw``
and ``reopen_session`` for ``open``. Matching is exact on the full dotted name
and, for entries marked ``bare``, on the final dotted segment — receivers like
``cursor`` cannot be resolved without type inference.

Reaching a sink is inventory; *using it unsafely* is a vulnerability.
``vuln_class`` selects the predicate in :mod:`cybergraph.security.predicates`,
and ``shell`` records whether the API runs a shell always, never, or depending
on a keyword — ``os.system`` and ``subprocess.run`` are not the same hazard.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

SHELL_NONE = "none"
SHELL_INHERENT = "inherent"
SHELL_CONDITIONAL = "conditional"


@dataclass(frozen=True)
class Sink:
    name: str
    rule_id: str
    cwe: str
    severity: str
    plain: str
    vuln_class: str
    bare: bool = False
    shell: str = SHELL_NONE


_CMD = "runs a system command built from this value"
_SQL = "sends this value to the database as part of a query"
_DESERIALIZE = "rebuilds objects from this value, which can run code"

_PYTHON: tuple[Sink, ...] = (
    Sink("subprocess.run", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.call", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.Popen", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.check_output", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("os.system", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_INHERENT),
    Sink("os.popen", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_INHERENT),
    Sink("eval", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("exec", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("pickle.loads", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("pickle.load", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("yaml.load", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executescript", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executemany", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("raw", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("render_template_string", "CG-TEMPLATE-INJECT", "CWE-1336", SEVERITY_HIGH,
         "renders this value as a template, which can run code", "template"),
    # `open` is matched by exact name only. As a bare sink it matched *any*
    # `x.open(...)`, which made `webbrowser.open(report.as_uri())` a high
    # CG-PATH-TRAVERSAL finding on this repository's own code. `bare` is for
    # receivers that cannot be resolved without type inference — `cursor.execute`
    # is one, and `open` is not: the builtin is spelled unqualified, and the
    # module-level spellings are enumerable.
    Sink("open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path"),
    Sink("io.open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path"),
    Sink("codecs.open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path"),
)

_JS_SQL = "sends this value to the database as part of a query"
_JS_CMD = "runs a system command built from this value"

_JAVASCRIPT: tuple[Sink, ...] = (
    # SQL — receivers (db/pool/knex/connection) are unresolvable → bare on the method name.
    Sink("query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    Sink("raw", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    # Command — exec/execSync spawn a shell (inherent); spawn/execFile take argv (conditional).
    Sink("child_process.exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD,
         "command", shell=SHELL_INHERENT),
    Sink("exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_INHERENT),
    Sink("execSync", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_INHERENT),
    Sink("spawn", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("execFile", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Code
    Sink("eval", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("Function", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    # Path — fs / fs.promises receivers unresolvable → bare on the method name.
    Sink("readFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("readFileSync", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("writeFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("writeFileSync", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("createReadStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
)

_GO: tuple[Sink, ...] = (
    # SQL — db/tx receivers unresolvable → bare on the PascalCase method name.
    Sink("Query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryRow", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryRowContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Exec", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command — exec.Command(name, args…); shell only when name is sh/bash -c → conditional.
    Sink("exec.Command", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         shell=SHELL_CONDITIONAL),
    Sink("exec.CommandContext", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         shell=SHELL_CONDITIONAL),
    # Path — os/ioutil receivers → bare on the PascalCase method name.
    Sink("Open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("Create", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
)

_JAVA: tuple[Sink, ...] = (
    # SQL (bare method names)
    Sink("executeQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executeUpdate", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("update", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("createNativeQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("createQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # `Statement.prepareStatement`/`prepareCall` build the query text itself --
    # a concatenated argument here is exactly as unsafe as `executeQuery` on the
    # concatenated string; the parameterized `?`-placeholder form is the safe
    # idiom, which is why grading these (rather than the argument-less
    # `.executeQuery()` that follows) is what actually catches a concatenated
    # PreparedStatement.
    Sink("prepareStatement", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("prepareCall", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command (bare; Runtime.exec / ProcessBuilder / .start)
    Sink("exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("ProcessBuilder", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("start", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Path (bare; incl. constructor sinks File / FileReader / FileWriter / FileInputStream)
    Sink("File", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileReader", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileWriter", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileInputStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("readAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("write", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    # Deserialization
    Sink("readObject", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
    Sink("readUnshared", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
)

_CSHARP: tuple[Sink, ...] = (
    # SQL (bare method names + Dapper); constructor SqlCommand handled by the analyzer's matcher.
    Sink("ExecuteReader", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteNonQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteScalar", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteReaderAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteNonQueryAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteScalarAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirst", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirstAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingle", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingleAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirstOrDefault", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingleOrDefault", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # SQL command constructors (matched by the analyzer on the type name).
    Sink("SqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("MySqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("NpgsqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("OracleCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("SqliteCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command (Process.Start / new ProcessStartInfo); shell only when the program is a shell.
    Sink("Start", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("ProcessStartInfo", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Path (bare methods + constructors StreamReader/StreamWriter/FileStream/FileInfo).
    Sink("ReadAllText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteAllText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadAllLines", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenRead", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenWrite", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("Delete", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("StreamReader", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("StreamWriter", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileInfo", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    # Deserialization (bare Deserialize/ReadObject -- covers the ysoserial.net formatters).
    Sink("Deserialize", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
    Sink("ReadObject", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
    # Code execution (exact dotted names, NOT bare).
    Sink("CSharpScript.EvaluateAsync", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpScript.RunAsync", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpScript.Create", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpCodeProvider.CompileAssemblyFromSource", "CG-CODE-EXEC", "CWE-95",
         SEVERITY_CRITICAL, "runs this value as program code", "code"),
)

_BY_LANGUAGE: dict[str, tuple[Sink, ...]] = {
    "python": _PYTHON,
    "javascript": _JAVASCRIPT,
    "go": _GO,
    "java": _JAVA,
    "csharp": _CSHARP,
}


def all_sinks() -> tuple[Sink, ...]:
    return tuple(sink for sinks in _BY_LANGUAGE.values() for sink in sinks)


def lookup_sink(call_name: str, language: str) -> Sink | None:
    """Exact match on the full dotted name, then the bare final segment."""
    sinks = _BY_LANGUAGE.get(language)
    if not sinks or not call_name:
        return None
    for sink in sinks:
        if sink.name == call_name:
            return sink
    tail = call_name.rsplit(".", 1)[-1]
    for sink in sinks:
        if sink.bare and sink.name == tail:
            return sink
    return None
