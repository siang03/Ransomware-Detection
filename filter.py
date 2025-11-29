import json
import os
import pandas as pd
import uuid
import numpy as np
from functools import reduce
from glob import glob
import time
import logging

# Import common logging configuration
import log_config

logger = logging.getLogger(__name__)

# Define all features
features = [
    'procmemory', 'file', 'urls', 'proc_pid', 'procm_extracted', 'name', 'type', 'ext_urls',
    'path', 'extracted', 'info', 'program', 'virustotal', 'vir_summary', 'positives', 'network',
    'udp', 'dns_servers', 'tcp', 'mitm', 'hosts', 'domains', 'dead_hosts', 'dns', 'request',
    'signatures', 'families', 'description', 'sign_name', 'marks', 'call', 'category', 'sign_stacktrace',
    'api', 'arguments', 'static', 'imported_dll_count', 'pe_imports', 'dll', 'pe_resources', 'pe_res_name',
    'filetype', 'pe_sections', 'pe_sec_name', 'entropy', 'behavior', 'apistats', 'processes', 'process_path',
    'pid', 'process_name', 'beh_command_line', 'ppid', 'processtree', 'tree_process_name', 'tree_command_line',
    'children', 'summary', 'file_created', 'dll_loaded', 'regkey_opened', 'wmi_query', 'command_line', 'file_read',
    'regkey_read', 'directory_enumerated', 'regkey_written', 'debug', 'action', 'errors', 'log'
]

df_dataset = pd.DataFrame()

def list_tofeature(values, name):
    global df_dataset
    df_dataset = pd.concat([df_dataset, pd.DataFrame(pd.Series(values), columns=[name])], axis=1)
    
def empty_category(names):
    for x in names:
        list_tofeature([], x)

def procmemory(features, data):
    available = ['file','urls','proc_pid']
    if 'procmemory' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    category = data['procmemory']
    selected = list(set(available).intersection(features))
    for x in selected:
        procmemory_feature = []
        for c in category:
            if x in c:
                procmemory_feature.append(c[x])
            elif x=='proc_pid' and 'pid' in c:
                procmemory_feature.append(c['pid'])
        if procmemory_feature:
            if x == 'proc_pid':
                list_tofeature(procmemory_feature, 'proc_pid')
            elif x == 'urls':
                list_tofeature(reduce(lambda a, b: a+b, procmemory_feature), x)
            else:
                list_tofeature(procmemory_feature, x)
        else:
            list_tofeature([], x)

def procmemory_extracted(features, data):
    available = ['name','type','ext_urls','path']
    if 'procmemory' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    procmemory_items = data['procmemory']
    selected = list(set(available).intersection(features))
    for x in selected:
        extracted_feature = []
        for item in procmemory_items:
            if 'extracted' in item:
                extracted_general = item['extracted']
                if extracted_general:
                    for extracted in extracted_general:
                        if x in extracted:
                            extracted_feature.append(extracted[x])
                        elif x=='ext_urls' and 'urls' in extracted:
                            extracted_feature.append(extracted['urls'])
        if extracted_feature:
            if x=='ext_urls':
                list_tofeature(reduce(lambda a, b: a+b, extracted_feature), x)
            else:
                list_tofeature(extracted_feature, x)
        else:
            list_tofeature([], x)

def behavior_processes(features, data):
    available = ['pid','process_name','ppid'] 
    if 'behavior' not in data or 'processes' not in data['behavior']:
        empty_category(['proc'])
        return
    category = data['behavior']['processes']
    beh_process_groups = []
    selected = list(set(available).intersection(features))
    for item in category:
        beh_process_group = {}
        for esc in selected:
            beh_process_group[esc] = item.get(esc, '')
        beh_process_groups.append(beh_process_group)
    list_tofeature(beh_process_groups, 'proc')

def behavior_processes_single_feature(features, data):
    available = ['process_path', 'beh_command_line'] 
    if 'behavior' not in data or 'processes' not in data['behavior']:
        empty_category(list(set(available).intersection(features)))
        return
    category = data['behavior']['processes']
    selected = list(set(available).intersection(features))
    for x in selected:
        process_feature = []
        for c in category:
            if x in c:
                process_feature.append(c[x])
            elif x=='beh_command_line' and 'command_line' in c:
                process_feature.append(c['command_line'])
        if process_feature:
            list_tofeature(process_feature, x)
        else:
            list_tofeature([], x)

def behavior_processes_set(features, data):
    available = ['call_category', 'status', 'call_stacktrace', 'call_arguments', 'tid'] 
    if 'behavior' not in data or 'processes' not in data['behavior']:
        empty_category(list(set(available).intersection(features)))
        return
    processes = data['behavior']['processes']
    selected = list(set(available).intersection(features))
    for feature in selected:
        process_feature = []
        for process in processes:
            if 'calls' in process:
                for call in process['calls']:
                    if feature in call:
                        process_feature.append(call[feature])
                    elif feature=='call_category' and 'category' in call:
                        process_feature.append(call['category'])
                    elif feature=='call_stacktrace' and 'stacktrace' in call:
                        process_feature.append(call['stacktrace'])
                    elif feature=='call_arguments' and 'arguments' in call:
                        process_feature.append(call['arguments'])
        if process_feature:
            if feature == 'call_stacktrace':
                list_tofeature(reduce(lambda a, b: a+b, process_feature), feature)
            else:
                list_tofeature(process_feature, feature)
        else:
            list_tofeature([], feature)
    
def behavior_processtree(features, data): 
    available = ['tree_process_name', 'tree_command_line', 'children'] 
    if 'behavior' not in data or 'processtree' not in data['behavior']:
        empty_category(list(set(available).intersection(features)))
        return
    processes = data['behavior']['processtree']
    selected = list(set(available).intersection(features))
    for feature in selected:
        process_feature = []
        for tree in processes:
            if feature in tree:
                process_feature.append(tree[feature])
            elif feature=='tree_process_name' and 'process_name' in tree:
                process_feature.append(tree['process_name'])
            elif feature=='tree_command_line' and 'command_line' in tree:
                process_feature.append(tree['command_line'])
        if process_feature:
            if feature == 'children':
                list_tofeature(reduce(lambda a, b: a+b, process_feature), feature)
            else:
                list_tofeature(process_feature, feature)
        else:
            list_tofeature([], feature)

def behavior_summary(features, data):
    available = ['file_created', 'dll_loaded', 'regkey_opened', 'command_line', 'regkey_read', 'regkey_written', 'wmi_query', 'file_read', 'directory_enumerated']
    if 'behavior' not in data or 'summary' not in data['behavior']:
        empty_category(list(set(available).intersection(features)))
        return
    selected = list(set(available).intersection(features))
    category = data['behavior']['summary']
    for x in selected:
        if x in category:
            clean_category = [s.replace(';', '') for s in category[x]]
            list_tofeature(clean_category, x)
        else:
            list_tofeature([], x)

def behavior_apistats(features, data):
    available = ['apistats']
    if 'behavior' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    behavior = data['behavior']
    if 'apistats' in behavior:
        apistats = behavior['apistats']
        keys = apistats.keys()
        main_list = []
        for key in keys:
            main_list.append(list(apistats[key].items()))
        if main_list:
            reduced = reduce(lambda a, b: a+b, main_list)    
            list_tofeature(reduced, 'apistats')
        else:
            empty_category(list(set(available).intersection(features)))
    else:
        empty_category(list(set(available).intersection(features)))
    
def network(features, data):
    available = ['udp', 'tcp', 'hosts', 'request', 'domains', 'dns_servers', 'dead_hosts', 'mitm']
    if 'network' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = list(set(available).intersection(features))
    for x in selected:
        category = data['network']
        if x in category:
            list_tofeature(category[x], x)
        elif x == 'request':
            if 'dns' in category:
                network_dns_requests = []
                for item in data['network']['dns']:
                    network_dns_requests.append(item['request'])
                list_tofeature(network_dns_requests, 'requests')
            else:
                list_tofeature([], x)	
        else:
            list_tofeature([], x)

def extracted(features, data):
    available = ['info', 'program']
    if 'extracted' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    extracted_items = data['extracted']
    selected = set(available).intersection(features)
    for x in selected:
        extracted_feature = []
        for y in extracted_items:
            if x in y:
                extracted_feature.append(y[x])
        if extracted_feature:
            list_tofeature(extracted_feature, x)
        else:
            list_tofeature([], x)

def virustotal(features, data):
    available = ['positives']
    if 'virustotal' not in data:
        empty_category(available)
        return
    virustotal_section = data['virustotal']
    if 'summary' not in virustotal_section:
        empty_category(available)
        return
    summary = virustotal_section['summary']
    if 'positives' not in summary:
        empty_category(available)
    else:
        list_tofeature([summary['positives']], 'positives')

def signatures(features, data):
    available = ['families', 'description', 'sign_name']
    if 'signatures' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = set(available).intersection(features)
    signatures_list = data['signatures']
    for x in selected:
        signature_feature = []
        for y in signatures_list:
            if x in y:
                signature_feature.append(y[x])
            elif x == 'sign_name' and 'name' in y:
                signature_feature.append(y['name'])
        if signature_feature:
            if x == 'families':
                list_tofeature(reduce(lambda a, b: a+b, signature_feature), x)
            else:
                list_tofeature(signature_feature, x)
        else:
            list_tofeature([], x)

def signatures_call(features, data):
    available = ['category', 'sign_stacktrace', 'api', 'arguments']
    if 'signatures' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = set(available).intersection(features)
    signatures_list = data['signatures']
    for x in selected:
        signature_feature = []
        for item in signatures_list:
            if 'marks' in item:
                marks_general = item['marks']
                if marks_general:
                    for mark in marks_general:
                        if 'call' in mark:
                            if x in mark['call']:
                                signature_feature.append(mark['call'][x])
                            elif x == 'sign_stacktrace' and 'stacktrace' in mark['call']:
                                signature_feature.append(mark['call']['stacktrace'])
        if signature_feature:
            if x == 'sign_stacktrace':
                list_tofeature(reduce(lambda a, b: a+b, signature_feature), x)
            else:
                list_tofeature(signature_feature, x)
        else:
            list_tofeature([], x)

def static_direct(features, data):
    available = ['imported_dll_count']
    if 'static' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    static = data['static']
    for x in available:
        if x in static:
            list_tofeature([static[x]], x)
        else:
            list_tofeature([], x)

def static_direct_set(features, data):
    sets = {
        'pe_imports': ['dll'],
        'pe_resources': ['pe_res_name', 'filetype'],
        'pe_sections': ['pe_sec_name', 'entropy']
    }
    if 'static' not in data:
        selected = []
        for att in sets.values():
            selected = [x for x in att if x in features] + selected
        empty_category(selected)
        return
    static = data['static']
    selected_keys = set(sets.keys()).intersection(features)
    for key in selected_keys:
        selected = [x for x in sets[key] if x in features]
        if key in static:
            for feature in selected:
                static_feature = []
                for item in static[key]:
                    if feature in item:
                        static_feature.append(item[feature])
                    elif feature == 'pe_res_name' and 'name' in item and key == 'pe_resources':
                        static_feature.append(item['name'])
                    elif feature == 'pe_sec_name' and 'name' in item and key == 'pe_sections':
                        static_feature.append(item['name'])
                if static_feature:
                    list_tofeature(static_feature, feature)
                else:
                    list_tofeature([], feature)
        else:
            empty_category(selected)

def debug(features, data):
    available = ['action', 'errors', 'log']
    if 'debug' not in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = list(set(available).intersection(features))
    debug_section = data['debug']
    for x in selected:
        if x in debug_section:
            list_tofeature(debug_section[x], x)
        else:
            list_tofeature([], x)

def process(file_path):
    # Generate output path based on input file
    separator = os.sep  # Handles OS-specific path separator
    start = time.time()
    
    # Ensure TEST directory exists
    test_dir = os.path.join(os.getcwd(), "TEST")
    os.makedirs(test_dir, exist_ok=True)
    
    # Generate the output file name based on the input file
    if file_path:
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        SAVE_PATH = os.path.join(test_dir, f"{base_name}_output.csv")
    else:
        unique_id = str(uuid.uuid4())
        SAVE_PATH = os.path.join(test_dir, f"{unique_id}.csv")

    global df_dataset
    df_dataset = pd.DataFrame()
    
    logger.info("Starting feature extraction. Empty dataset shape: %s", df_dataset.shape)
    logger.info("Features to extract: %s", features)

    # Wrap file reading and JSON parsing in try/except
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("File not found: %s", file_path)
        return None
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in file %s: %s", file_path, str(e))
        return None
    except Exception as e:
        logger.error("Unexpected error while reading %s: %s", file_path, str(e))
        return None
        
    try:
        if 'procmemory' in features:
            procmemory(features, data)
            if 'procm_extracted' in features:
                procmemory_extracted(features, data)
        if 'extracted' in features:
            extracted(features, data)
        if 'virustotal' in features:
            virustotal(features, data)
        if 'signatures' in features:
            signatures(features, data)
            if 'call' in features:
                signatures_call(features, data)
        if 'static' in features:
            if 'imported_dll_count' in features:
                static_direct(features, data)
            if 'pe_imports' in features or 'pe_resources' in features or 'pe_sections' in features:
                static_direct_set(features, data)
        if 'network' in features:
            network(features, data)
        if 'behavior' in features:
            if 'processes' in features:
                if 'pid' in features or 'process_name' in features or 'ppid' in features:
                    behavior_processes(features, data)
                behavior_processes_single_feature(features, data)
                if 'processtree' in features:
                    behavior_processtree(features, data)
            if 'summary' in features:
                behavior_summary(features, data)
            if 'apistats' in features:
                behavior_apistats(features, data)
        if 'debug' in features:
            debug(features, data)
    except Exception as e:
        logger.error("Error during feature extraction: %s", str(e))
        return None

    df_dataset = df_dataset.infer_objects(copy=False)
    df_dataset.fillna(np.nan, inplace=True)
    row_df = pd.DataFrame([df_dataset.count()])

    # Specify the desired column order
    columns_order = [
        "proc_pid", "file", "urls", "type", "name", "ext_urls", "path", "program", "info", "positives",
        "families", "description", "sign_name", "sign_stacktrace", "arguments", "api", "category",
        "imported_dll_count", "dll", "pe_res_name", "filetype", "pe_sec_name", "entropy", "hosts", "requests",
        "mitm", "domains", "dns_servers", "tcp", "udp", "dead_hosts", "proc", "beh_command_line",
        "process_path", "tree_command_line", "children", "tree_process_name", "command_line", "regkey_read",
        "directory_enumerated", "regkey_opened", "file_created", "wmi_query", "dll_loaded", "regkey_written",
        "file_read", "apistats", "errors", "action", "log"
    ]

    # Ensure row_df has the specified column order
    row_df = row_df.reindex(columns=columns_order)
    
    try:
        row_df.to_csv(SAVE_PATH, index=False)
        logger.info("Feature extraction complete. Output saved to: %s", SAVE_PATH)
    except Exception as e:
        logger.error("Failed to write output CSV: %s", str(e))
        return None

    end = time.time()
    print(f"(1) Runtime: {end - start} seconds")
    return SAVE_PATH

if __name__ == "__main__":
    process(file_path)

