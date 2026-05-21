import ast


def _truncate_poc_for_display(content: str) -> str:
    """
    Extracts the module-level docstring from a Python script for safe display.
    Prevents leakage of exploit logic.
    """
    if not content:
        return ""

    content = content.strip()

    # Try using AST to get the docstring cleanly
    try:
        tree = ast.parse(content)
        doc = ast.get_docstring(tree)
        if doc:
            return f'"""\n{doc.strip()}\n"""\n\n# ... [Exploit logic hidden] ...'
    except Exception as e:
        print(f"AST failed: {e}")

    # Fallback to manual triple-quote extraction if AST fails or docstring is missing
    for quote in ['"""', "'''"]:
        if content.startswith(quote):
            second_quote_idx = content.find(quote, len(quote))
            if second_quote_idx != -1:
                return (
                    content[: second_quote_idx + len(quote)].strip()
                    + "\n\n# ... [Rest of code hidden for security] ..."
                )

    # Second fallback: take first 15 lines if no obvious docstring
    lines = content.splitlines()
    if len(lines) > 15:
        return "\n".join(lines[:15]) + "\n\n# ... [Rest of code hidden for security] ..."

    return content


test_content = """\"\"\"
PoC Name: Test
Description: Hello
\"\"\"
import os
print("Hidden code")
"""

print("--- Result ---")
print(_truncate_poc_for_display(test_content))
print("--------------")
