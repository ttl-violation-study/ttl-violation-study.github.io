import json
import time
from collections import defaultdict
from multiprocessing.dummy import Pool as ThreadPool


main_file_base_directory = "xxx"
bind_file_directory = "xxx"
apache_file_directory = "xxx"

allowed_ttl = [1, 5, 15, 30, 60]

req_uid_to_response = {}
req_uid_to_response_time = {}
req_uid_to_phase_1_resolvers_all = defaultdict(lambda: set())
req_uid_to_phase_1_resolvers_without_lum = defaultdict(lambda: set())


def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


ip_to_index = {
    "3.223.194.233": 7,
    "34.226.99.56": 5,
    "52.44.221.99": 8,
    "52.71.44.50": 6,
    "18.207.47.246": 2,
    "3.208.196.0": 3,
    "44.195.175.12": 4,
    "50.16.6.90": 1,
}

chosen_meta = None
class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class Meta:
    def __init__(self):
        self.resolver_ip_to_verdict_list_dump = None
    pass


ttl_to_meta_dict = {}
ip_hash_to_asn_global = {}

all_resolver_set = list()
all_exitnode_set = set()
all_asn_set = set()
all_lum_resolver_set = set()
all_lum_exitnode_set = set()
all_lum_asn_set = set()

all_detected_resolvers = set()
all_detected_asns = set()
all_detected_exitnodes = set()

response_to_ip = {}

for ttl in allowed_ttl:
    meta = Meta()

    # (uid, asn, ip_hash, response_1, response_2)
    meta.dishonor_lst = []
    meta.honor_lst = []

    # both response
    meta.detected_resolvers = set()
    meta.detected_asns = set()
    meta.detected_exitnodes = set()

    # (resolver_ip, float(timestamp))
    meta.req_uid_to_phase_1_resolver_tuple = {}

    # ip er list just TODO think !!
    meta.req_uid_to_phase_2_resolver_lst = defaultdict(lambda: list())

    # only one phase successful holei
    meta.req_uid_to_asn = {}
    meta.req_uid_to_hash = {}
    meta.req_dict = {} # contains response 1

    meta.found_set = set()
    meta.not_found_set = set()

    ttl_to_meta_dict[ttl] = meta


for key in ip_to_index:
    response_to_ip["phase{}".format(ip_to_index[key])] = key


def analyze_bind_leaf(file):
    global req_uid_to_phase_1_resolvers_all
    global req_uid_to_phase_1_resolvers_without_lum
    with open(file) as FileObj:
        for line in FileObj:
            try:
                non_decidings_ips = ['52.4.120.223']
                if "good" not in line or "zeus_reload" not in line:
                    continue

                segments = line.strip().split()
                resolver_ip, timestamp, allotted_ip, req_url = segments[1], segments[2], segments[3], segments[4]
                req_uid = req_url.split(".")[0]
                ttl = int(req_url.split(".")[2])

                meta = ttl_to_meta_dict[ttl]

                all_resolver_set.append(resolver_ip)

                if allotted_ip != '3.220.52.113':
                    req_uid_to_phase_1_resolvers_all[req_uid].add((resolver_ip, timestamp))

                try:
                    all_asn_set.add(meta.req_uid_to_asn[req_uid])
                    all_exitnode_set.add(meta.req_uid_to_hash[req_uid])
                except:
                    pass

                if allotted_ip in non_decidings_ips:
                    all_lum_resolver_set.add(resolver_ip)
                    continue

                response = meta.req_dict[req_uid]
                real_allotted_ip = response_to_ip[response]

                if allotted_ip == '3.220.52.113':
                    meta.req_uid_to_phase_2_resolver_lst[req_uid].append(resolver_ip)
                else:
                    req_uid_to_phase_1_resolvers_without_lum[req_uid].add((resolver_ip, timestamp))
                    if allotted_ip == real_allotted_ip:
                        if req_uid not in meta.req_uid_to_phase_1_resolver_tuple:
                            meta.req_uid_to_phase_1_resolver_tuple[req_uid] = (resolver_ip, float(timestamp))
                        else:
                            _, t = meta.req_uid_to_phase_1_resolver_tuple[req_uid]
                            if float(timestamp) < t:
                                meta.req_uid_to_phase_1_resolver_tuple[req_uid] = (resolver_ip, float(timestamp))
                # meta.found_set.add(req_uid)
            except Exception as e:
                # TODO severe inspect
                pass


def analyze_bind():
    global ttl_to_meta_dict

    leaf_files_unfiltered = get_leaf_files(bind_file_directory)

    pool = ThreadPool(50)
    results = pool.map(analyze_bind_leaf, leaf_files_unfiltered)
    pool.close()
    pool.join()


def analyze_main_file_leaf(exp_id):
    global req_uid_to_response
    meta = chosen_meta
    level_timestamp = exp_id.split("_")[-2]
    mid_Str = exp_id.split("_")[-1]
    # TODO change_mid_str
    full_file = "{}{}/{}/{}-out.json".format(main_file_base_directory.replace("xxx", str(ttl)), 2,
                                             level_timestamp, exp_id)
    f = open(full_file)
    d = json.load(f)

    for num in d['dict_of_phases']:
        try:
            response_1 = d['dict_of_phases'][num]['1-response'].strip()[4: -5]
            req_url_uid = d['dict_of_phases'][num]['req_url'][7:].split(".")[0]

            response_time = d['dict_of_phases'][num]['1-time']

            req_uid_to_response[req_url_uid] = response_1
            req_uid_to_response_time[req_url_uid] = response_time

            meta.req_uid_to_asn[req_url_uid] = d['dict_of_phases'][num]['asn']
            meta.req_uid_to_hash[req_url_uid] = d['dict_of_phases'][num]['ip_hash']
            meta.req_dict[req_url_uid] = response_1

            response_2 = d['dict_of_phases'][num]['2-response'].strip()[4: -5]

            ip_hash_to_asn_global[d['dict_of_phases'][num]['ip_hash']] = d['dict_of_phases'][num]['asn']

            save_tuple = (req_url_uid, d['dict_of_phases'][num]['asn'],
                          d['dict_of_phases'][num]['ip_hash'], response_1, response_2)

            if "lum" in response_1:
                continue

            if "phasex" not in response_2:
                if response_1 != response_2:
                    # weird TODO
                    pass
                else:
                    # url, asn, ip_hash, r1, r2
                    meta.dishonor_lst.append(save_tuple)
            else:
                meta.honor_lst.append(save_tuple)

        except Exception as e:
            # TODO
            pass
    return 1


def analyze_main_files(ttl):
    global chosen_meta
    global ttl_to_meta_dict
    chosen_meta = ttl_to_meta_dict[ttl]

    leaf_files_unfiltered = get_leaf_files(main_file_base_directory.replace("xxx", str(ttl)))
    leaf_files_filtered = [e.split("/")[-1] for e in leaf_files_unfiltered]
    leaf_files_filtered = [e for e in leaf_files_filtered if ".json" in e]

    exp_id_list = []
    for element in leaf_files_filtered:
        exp_id_list.append(element[: - len("-out.json")])

    pool = ThreadPool(50)
    results = pool.map(analyze_main_file_leaf, exp_id_list)
    pool.close()
    pool.join()

# TTL str na onno kichu

def dump_files():
    mother_info = {}
    global_resolver_set = set()
    global_asn_set = set()
    global_exitnode_set = set()

    for ttl in allowed_ttl:
        meta = ttl_to_meta_dict[ttl]
        mother_info[ttl] = {}
        mother_info[ttl]["total_resolvers"] = len(meta.detected_resolvers)
        global_resolver_set.update(meta.detected_resolvers)
        mother_info[ttl]["total_exitnodes"] = len(meta.detected_exitnodes)
        global_exitnode_set.update(meta.detected_exitnodes)
        mother_info[ttl]["total_asns"] = len(meta.detected_asns)
        global_asn_set.update(meta.detected_asns)
        mother_info[ttl]["resolver_ip_to_verdict_list_dump"] = meta.resolver_ip_to_verdict_list_dump

    mother_info["global"] = {}
    mother_info["global"]["total_resolvers"] = len(global_resolver_set)
    mother_info["global"]["total_exitnodes"] = len(global_exitnode_set)
    mother_info["global"]["total_asns"] = len(global_asn_set)

    mother_info["global_all"] = {}
    mother_info["global_all"]["total_resolvers"] = len(set(all_resolver_set))
    mother_info["global_all"]["total_exitnodes"] = len(all_exitnode_set)
    mother_info["global_all"]["total_asns"] = len(all_asn_set)
    mother_info["global_all"]["lum_resolvers"] = len(all_lum_resolver_set)
    mother_info["time_of_parse"] = time.time()
    from pathlib import Path


    # set it
    dump_directory = "dump"

    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    with open(dump_directory + "mother_info.json", "w") as ouf:
        json.dump(mother_info, fp=ouf, cls=SetEncoder)

    with open(dump_directory + "all_resolvers.json", "w") as ouf:
        json.dump(list(all_resolver_set), fp=ouf)

    mom = {
        "req_uid_to_phase_1_resolvers_all": req_uid_to_phase_1_resolvers_all,
        "req_uid_to_phase_1_resolvers_without_lum": req_uid_to_phase_1_resolvers_without_lum,
        "req_uid_to_response": req_uid_to_response,
        "req_uid_to_response_time": req_uid_to_response_time
    }

    # ip_hash_to_asn_global
    with open(dump_directory + "meta.json", "w") as ouf:
        json.dump(mom, fp=ouf, cls=SetEncoder)

    with open(dump_directory + "ip_hash_to_asn_global.json", "w") as ouf:
        json.dump(ip_hash_to_asn_global, fp=ouf, cls=SetEncoder)


def init(ttl):
    global ttl_to_meta_dict
    meta = ttl_to_meta_dict[ttl]

    resolver_ip_to_verdict_list = defaultdict(lambda: {"g": set(), "b": set()})
    resolver_ip_to_verdict_list_dump = defaultdict(lambda: {"g": list(), "b": list()})

    for e in meta.dishonor_lst:
        try:
            req_uid, asn, ip_hash, r1, r2 = e
            culprit_resolver = meta.req_uid_to_phase_1_resolver_tuple[req_uid][0]
            if culprit_resolver not in meta.req_uid_to_phase_2_resolver_lst[req_uid]:
                resolver_ip_to_verdict_list[culprit_resolver]["b"].add(ip_hash)
                meta.detected_resolvers.add(culprit_resolver)
                meta.detected_asns.add(asn)
                meta.detected_exitnodes.add(ip_hash)
        except:
            pass

    for e in meta.honor_lst:
        try:
            req_uid, asn, ip_hash, r1, r2 = e
            good_resolver = meta.req_uid_to_phase_1_resolver_tuple[req_uid][0]
            if ip_hash not in resolver_ip_to_verdict_list[good_resolver]["b"] and \
                    good_resolver in meta.req_uid_to_phase_2_resolver_lst[req_uid]:
                resolver_ip_to_verdict_list[good_resolver]["g"].add(ip_hash)
                meta.detected_resolvers.add(good_resolver)
                meta.detected_asns.add(asn)
                meta.detected_exitnodes.add(ip_hash)
            elif ip_hash in resolver_ip_to_verdict_list[good_resolver]["b"]:
                resolver_ip_to_verdict_list[good_resolver]["b"].remove(ip_hash)
        except:
            pass

    for resolver in resolver_ip_to_verdict_list:
        resolver_ip_to_verdict_list_dump[resolver]["g"] = list(resolver_ip_to_verdict_list[resolver]["g"])
        resolver_ip_to_verdict_list_dump[resolver]["b"] = list(resolver_ip_to_verdict_list[resolver]["b"])

    meta.resolver_ip_to_verdict_list_dump = resolver_ip_to_verdict_list_dump


start_time = time.time()

for ttl in allowed_ttl:
    analyze_main_files(ttl=ttl)

for ttl in allowed_ttl:
    print(ttl, len(ttl_to_meta_dict[ttl].dishonor_lst))

analyzed_node_time = time.time()
print("Analyze time {}".format((analyzed_node_time - start_time) / 60))

analyze_bind()
# req_uid_to_phase_1_resolver_tuple
for ttl in allowed_ttl:
    print(ttl, len(list(ttl_to_meta_dict[ttl].req_uid_to_phase_1_resolver_tuple.keys())))

analyzed_bind_time = time.time()
print("Bind time {}".format((analyzed_bind_time - start_time) / 60))

for ttl in allowed_ttl:
    init(ttl)

analyzed_init_time = time.time()
print("Total time {}".format((analyzed_init_time - start_time) / 60))

dump_files()
print("Dumped files")