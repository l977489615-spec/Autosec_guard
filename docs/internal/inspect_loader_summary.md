# Edge plugin loader inspection summary

## Files inspected
- `server/poc_worker.py`
- `server/sandbox_runner.py`
- `server/pocs/iv_plugin_base.py`
- `server/pocs/99_Dynamic_0Day.py`

## Edge execution path
1. `server/poc_worker.py` builds a `PocWorkerPlan`.
2. It launches `server/sandbox_runner.py` as a subprocess:
   - command shape: `python sandbox_runner.py <poc_path> <params_json>`
3. `sandbox_runner.py` imports the target PoC module from its file path with `importlib.util.spec_from_file_location(...)`.
4. After import, `sandbox_runner.py` scans the imported module for a plugin class.
5. If found, it instantiates the class with `plugin_class(params)`.
6. It calls `plugin.run_verify()`.
7. It prints a result marker `===RESULT_TOKEN===` followed by JSON built from `plugin.results`.

## Exact plugin discovery logic in `server/sandbox_runner.py`
The loader does **not** require an explicit class name, but it does require a class matching this runtime shape:

- must be a class object: `isinstance(attr, type)`
- class name must **not** be `IVIVulnerabilityPlugin`
- class must have a `run_verify` attribute: `hasattr(attr, 'run_verify')`

The first module attribute matching those rules is selected as `plugin_class`.

## Practical expectations for a valid PoC plugin
For edge execution to work, a PoC file must define at least one importable class that:
- is present at module top level
- is not named `IVIVulnerabilityPlugin`
- exposes `run_verify` (normally by inheriting from `IVIVulnerabilityPlugin`)
- can be instantiated with one argument: `plugin_class(params)`
- populates `self.results` in the format expected by the runner, or at least remains compatible with the base class contract

## Base class contract from `server/pocs/iv_plugin_base.py`
The intended plugin base is `IVIVulnerabilityPlugin`.

Expected pattern:
- subclass `IVIVulnerabilityPlugin`
- implement:
  - `check_prerequisites(self)`
  - `exploit(self)`
- rely on inherited `run_verify(self)` to execute standardized flow
- use inherited `self.results` dict with keys such as:
  - `vulnerable`
  - `cve_id`
  - `description`
  - `evidence`

The base class constructor expects a dict-like `target_config` and sets fields like:
- `self.target_ip`
- `self.target_port`
- `self.interface`
- `self.timeout`
- `self.params`
- `self.results`

## Why a file returns `{"error":"No valid plugin class found"}`
That exact error is emitted in `server/sandbox_runner.py` when module import succeeds but no class in the module satisfies the discovery test.

A file can trigger this if:
- it defines no classes at all
- it only defines functions/script code
- it defines only the base class name `IVIVulnerabilityPlugin`
- its class does not expose `run_verify`
- its class is nested or otherwise not visible as a normal module attribute after import

## Root cause for `server/pocs/99_Dynamic_0Day.py`
`99_Dynamic_0Day.py` is a standalone script, not a plugin module:
- it defines top-level variables
- it defines functions `telnet_bruteforce(...)` and `ssh_bruteforce(...)`
- it has `if __name__ == "__main__": ...` script execution logic
- it defines **no class**
- therefore it defines no class with `run_verify`

So the loader imports the file successfully, scans `dir(module)`, finds no eligible class, and returns:
- `{"error":"No valid plugin class found"}`

## Important note on naming vs inheritance
There is no strict class-name convention in the loader besides excluding the literal base class name `IVIVulnerabilityPlugin`.

However, in practice the safe/expected convention is:
- define a concrete subclass of `IVIVulnerabilityPlugin`

That ensures:
- `run_verify` exists
- constructor signature is compatible
- `results` exists
- metadata fields can be read consistently elsewhere

## Additional loader-related observations
- `poc_worker.py` separately parses metadata from AST using class-level assignments like:
  - `meta_poc_name`
  - `meta_cve_id`
  - `meta_severity`
  - `meta_protocol`
  - `meta_target_os`
  - `meta_required_params`
  - `meta_destructive_level`
  - `is_disruptive`
- This metadata extraction does not validate subclassing; it just inspects class assignments.
- So a PoC could still produce some metadata in planning but fail at runtime if it does not define a loadable plugin class.
- `sandbox_runner.py` inserts both the PoC directory and `server/pocs` into `sys.path`, and also explicitly loads `iv_plugin_base.py` into `sys.modules['iv_plugin_base']` to support imports like `from iv_plugin_base import IVIVulnerabilityPlugin`.

## Exact minimum shape a working PoC should follow
A compatible PoC should look conceptually like:
- import `IVIVulnerabilityPlugin` from `iv_plugin_base`
- define one top-level subclass, e.g. `class Something(IVIVulnerabilityPlugin):`
- optionally set class metadata fields
- implement `check_prerequisites`
- implement `exploit`
- let inherited `run_verify` handle execution

Without that class-based structure, edge execution will not treat the PoC as valid.
