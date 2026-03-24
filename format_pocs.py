import os
import re

pocs_dir = '/Users/queen/Desktop/ICV_POC_research/autosec-guard---icv-vulnerability-scanner/server/pocs'

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Extract Docstring
    # Match the first block of """ ... """
    doc_match = re.search(r'^\"\"\"(.*?)\"\"\"', content, re.DOTALL)
    if not doc_match:
        return False
    doc_content = doc_match.group(1).strip()
    
    # Parse docstring into dictionary
    info = {
        'PoC Name': 'N/A',
        'CVE': 'N/A',
        'Component': 'N/A',
        'Category': 'N/A',
        'Severity': 'N/A',
        'CVSS': 'N/A',
        'Description': 'N/A',
        'Prerequisites': 'N/A',
        'Usage': 'N/A'
    }
    
    for line in doc_content.split('\n'):
        if ':' in line:
            parts = line.split(':', 1)
            key = parts[0].strip()
            val = parts[1].strip()
            # fuzzy match keys
            for k in info.keys():
                if k.lower() == key.lower():
                    info[k] = val
                    break
    
    new_docstring = f'\"\"\"\n'
    for k in info.keys():
        new_docstring += f'{k}: {info[k]}\n'
    new_docstring += f'\"\"\"'
    
    # Extract the usage from original docstring if 'Usage' wasn't captured correctly
    usage_match = re.search(r'^Usage:\s*(.*)', doc_content, re.MULTILINE | re.IGNORECASE)
    if usage_match:
        info['Usage'] = usage_match.group(1).strip()
    else:
        # try to get from print("Usage:...")
        pass
    
    new_docstring = (
        f'\"\"\"\n'
        f'PoC Name: {info["PoC Name"]}\n'
        f'CVE: {info["CVE"]}\n'
        f'Component: {info["Component"]}\n'
        f'Category: {info["Category"]}\n'
        f'Severity: {info["Severity"]}\n'
        f'CVSS: {info["CVSS"]}\n'
        f'Description: {info["Description"]}\n'
        f'Prerequisites: {info["Prerequisites"]}\n'
        f'Usage: {info["Usage"]}\n'
        f'\"\"\"'
    )

    # 2. Extract __main__ block
    main_match = re.search(r'if __name__ == "__main__":(.*)', content, re.DOTALL)
    if not main_match:
        return False
    main_body = main_match.group(1)
    
    # Extract plugin instantiation
    # e.g. plugin = BTHFPUAFPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin_match = re.search(r'plugin\s*=\s*([A-Za-z0-9_]+)\((.*?)\)', main_body)
    if not plugin_match:
        # maybe config = {...}; plugin = Class(config)
        plugin_class_match = re.search(r'([A-Za-z0-9_]+)\(', main_body)
        if plugin_class_match:
            plugin_class = plugin_class_match.group(1)
        else:
            plugin_class = "Plugin"
            
        config_match = re.search(r'config\s*=\s*({[^}]+})', main_body, re.DOTALL)
        if config_match:
            config_str = config_match.group(1)
        else:
            config_str = "{}"
    else:
        plugin_class = plugin_match.group(1)
        config_str = plugin_match.group(2)
        
    usage_print_match = re.search(r'print\(\"(.*?)\"\)', main_body)
    usage_print = usage_print_match.group(1) if usage_print_match else info["Usage"]
    # If the print is "Usage: python poc.py <ip>", we use that.
    
    # How many args?
    # sys.argv[1], sys.argv[2]
    import ast
    sys_argv_indices = set(re.findall(r'sys\.argv\[(\d+)\]', main_body))
    max_idx = max([int(x) for x in sys_argv_indices]) if sys_argv_indices else 1
    req_len = max_idx + 1

    # Format the new main block
    # Note: re-indent the config string to match properly
    config_str = config_str.replace('\n', ' ').strip()
    # collapse multiple spaces
    config_str = re.sub(r'\s+', ' ', config_str)
    
    new_main = (
        f'if __name__ == "__main__":\n'
        f'    if len(sys.argv) < {req_len}:\n'
        f'        print("{usage_print}")\n'
        f'        sys.exit(1)\n'
        f'    plugin = {plugin_class}({config_str})\n'
        f'    plugin.run_verify()\n'
    )
    
    # Replace the parts
    content = content.replace(doc_match.group(0), new_docstring)
    content = content.replace(main_match.group(0), " " + new_main)
    # wait, main_match.group(0) is the text from 'if __name__' to EOF.
    # so we just replace the whole thing.
    
    new_content = content[:content.find('if __name__ == "__main__":')] + new_main
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
        
    return True

success_count = 0
for root, dirs, files in os.walk(pocs_dir):
    for f in files:
        if f.endswith('.py') and not f.startswith('__'):
            path = os.path.join(root, f)
            if process_file(path):
                success_count += 1
            else:
                print("Failed to process:", f)
                
print(f"Processed {success_count} files.")
