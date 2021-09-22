import collections
import traceback
import re
import math


def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    normalized_ent = 0
    n = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            n += 1
            entropy += - p_x*math.log(p_x, 2)

    if math.log(n) > 0:
        normalized_ent = entropy / math.log(n, 2)
    return entropy, normalized_ent


def get_paths(source):
    paths = []
    if isinstance(source, collections.MutableMapping):
        for k, v in source.items():
            paths.append([k])
            paths += [[k] + x for x in get_paths(v)]
    elif isinstance(source, collections.Sequence) and not isinstance(source, str):
        for i, v in enumerate(source):
            paths.append([i])
            paths += [[i] + x for x in get_paths(v)]
    return paths


def secret_finder(snapshot, PASSWORD_VALUE_RE, PASSWORD_KEY_RE=None, EXCLUDE_RE=None, shannon_entropy_password=False):
    output = {}
    entropy_list = []
    try:
        issue_found = False
        skipped = True
        if isinstance(snapshot.get("Resources"), list):
            for resource in snapshot.get("Resources"):
                skipped = False
                path_list = get_paths(resource)
                for path in path_list:
                    nested_resource = resource
                    for key in path:
                        nested_resource = nested_resource[key]
                        if isinstance(nested_resource, str) and re.match(PASSWORD_VALUE_RE, nested_resource) and (re.match(PASSWORD_KEY_RE, str(key), re.I) if PASSWORD_KEY_RE else True) and (not(re.match(EXCLUDE_RE, str(nested_resource))) if EXCLUDE_RE else True):
                            if shannon_entropy_password:
                                _, normalized_entropy = shannon_entropy(
                                    nested_resource)
                                if normalized_entropy > 0.965:
                                    entropy_list.append({
                                        "path": "Resources/"+resource.get("Type")+"/" + "/".join([str(path) for path in path]),
                                        "value": nested_resource
                                    })
                                    issue_found = True
                                    print("\n\n")
                                    print("Resource Type:",
                                          resource.get("type"))
                                    print("Path to leaked password:", path)
                                    print("leaked password:", nested_resource)
                                    print("\n")
                                else:
                                    print(normalized_entropy, nested_resource)
                            else:
                                issue_found = True
                                print("\n\n")
                                print("Resource Type:", resource.get("type"))
                                print("Path to leaked password:", path)
                                print("leaked password:", nested_resource)
                                print("\n")

        output["issue"] = True if issue_found else False

        if entropy_list:
            output["entropy_password"] = entropy_list
        output["skipped"] = skipped
        return output
    except Exception as ex:
        print(traceback.format_exc())
        output["issue"] = None
        output["err"] = str(ex)
        output["skipped"] = skipped
        return output
