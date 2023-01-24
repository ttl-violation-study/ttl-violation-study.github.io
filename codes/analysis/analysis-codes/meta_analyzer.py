
allowed_ttl = ["1", "5", "15", "30", "60"]
from collections import defaultdict
import json
import pyasn
from asn_org_tools.org_finder import AS2ISP
from multiprocessing.dummy import Pool as ThreadPool
import time
asndb = pyasn.pyasn('asn_org_tools/data/ipsan_db.dat')
as2isp = AS2ISP()

parent_path = "data/"
asn_to_org_cn = {}
ip_to_asn = {}


f2 = open("alpha2.json")
d2 = json.load(f2)
alpha2_to_country = {}

for e in d2:
    c_code = e['country-code']
    a_2_code = e['alpha-2']
    alpha2_to_country[a_2_code] = e['name']


def get_verdict_list(ttl):
    f = open("dump/mother_info.json")
    d = json.load(f)
    return d[str(ttl)]['resolver_ip_to_verdict_list_dump']


def get_asn(ip):
    if ip in ip_to_asn:
        return ip_to_asn[ip]
    asn = asndb.lookup(ip)[0]
    ip_to_asn[ip] = asn
    return asn


def get_org_cn(asn):
    if asn in asn_to_org_cn:
        return asn_to_org_cn[asn]
    org, cn = str(as2isp.getISP("20221212", asn)[0]), str(as2isp.getISP("20221212", asn)[1])
    asn_to_org_cn[asn] = org, cn
    return org, cn

ip_to_org_cn = {}


def get_org_cn_from_ip(ip):
    if ip in ip_to_org_cn:
        return ip_to_org_cn[ip]
    return -1, -1


def preprocess_resolver(ip):
    if ip not in ip_to_org_cn:
        try:
            asn = get_asn(ip)
            org, cn = get_org_cn(asn)
            ip_to_org_cn[ip] = org, cn
        except:
            # print(ip)
            pass


# desc: resolver to org, asn mapping
def preprocess_resolvers():
    f = open("dump/mother_info.json")
    d = json.load(f)
    resolver_set = set()

    for ttl in allowed_ttl:
        for resolver in d[str(ttl)]['resolver_ip_to_verdict_list_dump']:
            resolver_set.add(resolver)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, list(resolver_set))
    pool.close()
    pool.join()


# desc: resolver to org, asn mapping global
def preprocess_all_resolvers():
    f = open("dump/all_resolvers.json")
    d = json.load(f)
    resolver_list = list(d)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, resolver_list)
    pool.close()
    pool.join()

    asn_list = list()
    for resolver in resolver_list:
        asn_list.append(ip_to_asn[resolver])

    with open(parent_path + "resolver_asn_list.json", "w") as ouf:
        json.dump(asn_list, fp=ouf)

    with open(parent_path + "ip_to_asn_dict.json", "w") as ouf:
        json.dump(ip_to_asn, fp=ouf)


def table_maker_local():
    org_to_local_count = defaultdict(lambda : 0)
    for ttl in allowed_ttl:
        final_dict = get_verdict_list(ttl)

        ans = defaultdict(lambda: [0, set()])
        c_ans = defaultdict(lambda: [0, set()])
        cn = {}
        org_set = set()

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            if total < 5:
                continue

            ratio = len(incorrect_set) / total

            if ratio >= 1:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                ans[org][0] += 1
                ans[org][1].update(total_set)
                cn[org] = cntry

                if is_local[key]:
                    org_to_local_count[org] += 1

                org_set.add(org)

            elif ratio <= 0:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                c_ans[org][0] += 1
                c_ans[org][1].update(total_set)
                cn[org] = cntry

                if is_local[key]:
                    org_to_local_count[org] += 1

                org_set.add(org)

        ans_lst = []

        for org in org_set:
            correct_count = 0
            in_correct_count = 0
            exitnode_set = set()
            if org in c_ans:
                correct_count = c_ans[org][0]
                exitnode_set = exitnode_set.union(c_ans[org][1])
            if org in ans:
                in_correct_count = ans[org][0]
                exitnode_set = exitnode_set.union(ans[org][1])

            local_count = org_to_local_count[org]
            local_perc = (local_count/(correct_count + in_correct_count)) * 100

            ans_lst.append((correct_count, in_correct_count, len(exitnode_set), org, cn[org], local_perc))

        with open(parent_path + "table_data.json", "w") as ouf:
            json.dump(ans_lst, fp=ouf)


def table_maker_global():
    org_to_local_count = defaultdict(lambda : 0)

    for ttl in allowed_ttl:

        final_dict = get_verdict_list(ttl)
        ans = defaultdict(lambda: [0, set()])
        c_ans = defaultdict(lambda: [0, set()])
        cn = {}
        org_set = set()

        for key in final_dict:

            if not is_local[key]:
                continue

            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            if total < 5:
                continue

            ratio = len(incorrect_set) / total



            if ratio >= 1:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                ans[org][0] += 1
                ans[org][1].update(total_set)
                cn[org] = cntry
                # print(org)
                org_set.add(org)

                if cntry == 'BR':
                    print(key, cntry, total)

            elif ratio <= 0:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                c_ans[org][0] += 1
                c_ans[org][1].update(total_set)
                cn[org] = cntry

                org_set.add(org)

        ans_lst = []

        country_to_meta = defaultdict(lambda : list())

        for org in org_set:
            cnn = cn[org]
            correct_count = 0
            in_correct_count = 0
            exitnode_set = set()
            incorrect_exitnode = set()
            correct_exitnode = set()

            if org in c_ans:
                correct_count = c_ans[org][0]
                exitnode_set = exitnode_set.union(c_ans[org][1])
                correct_exitnode.update(c_ans[org][1])
            if org in ans:
                in_correct_count = ans[org][0]
                exitnode_set = exitnode_set.union(ans[org][1])
                incorrect_exitnode.update(ans[org][1])

            meta = {
                "organization": org,
                "honoring_resolvers": correct_count,
                "extending_resolvers": in_correct_count,
                "percentage_of_extending_resolvers": (in_correct_count/(correct_count + in_correct_count)) * 100,
                "total_exitnodes": len(exitnode_set),
                "exitnodes_with_stale_response": len(incorrect_exitnode),
                "percentage_of_exitnodes_with_stale_response": (len(incorrect_exitnode)/len(exitnode_set)) * 100
            }
            # print(alpha2_to_country[cn])
            cd = cnn
            if cnn in alpha2_to_country:
                cd = alpha2_to_country[cnn]
            country_to_meta[cd].append(meta)
            #ans_lst.append((correct_count, in_correct_count, len(exitnode_set), org, cn[org]))

        header = ['country', 'organization', 'extending_resolvers', 'total_resolvers',
                  'percentage_of_extending_resolvers',
                  'exitnodes_with_stale_response', 'total_exitnodes',
                  'percentage_of_exitnodes_with_stale_response']

        import csv
        with open(parent_path + 'ttl_extension_organization_table.csv', 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            import csv
            writer.writerow(header)
            for cn in country_to_meta:
                for e in country_to_meta[cn]:
                    row = [cn, e['organization'], e['extending_resolvers'], e['honoring_resolvers'] + e['extending_resolvers'], e['percentage_of_extending_resolvers'],
                           e['exitnodes_with_stale_response'], e['total_exitnodes'],
                           e['percentage_of_exitnodes_with_stale_response']]
                    writer.writerow(row)

        with open(parent_path + "table_data_local.json", "w") as ouf:
            json.dump(country_to_meta, fp=ouf, indent=2)


def get_client_to_country_distro():
    f = open("dump/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)
    cn_to_exitnode_set = defaultdict(lambda: set())
    exitnode_set = set()
    cn_to_perc_list = []
    for ttl in allowed_ttl:
        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            for e in final_dict[key]["b"]:
                client_asn = ip_hash_to_asn[e]
                exitnode_set.add(e)
                org, cntry = get_org_cn(client_asn)
                cn_to_exitnode_set[cntry].add(e)

            for e in final_dict[key]["g"]:
                client_asn = ip_hash_to_asn[e]
                exitnode_set.add(e)
                org, cntry = get_org_cn(client_asn)
                cn_to_exitnode_set[cntry].add(e)

    for cn in cn_to_exitnode_set:
        cn_to_perc_list.append((len(cn_to_exitnode_set[cn])/len(exitnode_set), cn, len(cn_to_exitnode_set[cn])))
    cn_to_perc_list.sort(reverse=True)

    with open("cn_to_perc_list.json", "w") as ouf:
        json.dump(cn_to_perc_list, fp=ouf)


def geographic_dishonoring_resolver_distro():
    inc_set = set()
    cor_set = set()
    all_set = set()

    for ttl in allowed_ttl:

        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            if total < 5:
                continue

            ratio = len(incorrect_set) / total

            if ratio >= 1:
                inc_set.add(key)
            elif ratio <= 0:
                cor_set.add(key)

    cor_set = cor_set.difference(inc_set)
    all_set = cor_set.union(inc_set)

    geo_distro = {}

    country_code_to_count_map = defaultdict(lambda: 0)

    for resolver in inc_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["incorrect"] = country_code_to_count_map

    country_code_to_count_map = defaultdict(lambda: 0)
    for resolver in cor_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["correct"] = country_code_to_count_map

    country_code_to_count_map = defaultdict(lambda: 0)
    for resolver in all_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["all"] = country_code_to_count_map

    with open(parent_path + "geographic_corr_incorr_distro_global.json", "w") as ouf:
        json.dump(geo_distro, fp=ouf)


def geographic_exitnode_fraction():

    resolver_to_bad_exit_nodes = defaultdict(lambda: set())
    resolver_to_good_exit_nodes = defaultdict(lambda: set())

    country_to_good_exit_nodes = defaultdict(lambda: set())
    country_to_bad_exit_nodes = defaultdict(lambda: set())

    for ttl in allowed_ttl:
        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            resolver_to_bad_exit_nodes[key].update(incorrect_set)
            resolver_to_good_exit_nodes[key].update(correct_set)

    country_set = set()

    for resolver in resolver_to_bad_exit_nodes:
        cn = get_org_cn_from_ip(resolver)[1]
        country_set.add(cn)
        country_to_bad_exit_nodes[cn].update(resolver_to_bad_exit_nodes[resolver])

    for resolver in resolver_to_good_exit_nodes:
        cn = get_org_cn_from_ip(resolver)[1]
        country_set.add(cn)
        country_to_good_exit_nodes[cn].update(resolver_to_good_exit_nodes[resolver])

    country_to_meta = {}
    for cn in country_set:
        total_set = country_to_bad_exit_nodes[cn].union(country_to_good_exit_nodes[cn])
        bad_set = country_to_bad_exit_nodes[cn]
        if len(total_set) == 0:
            continue
        percentage_of_bad_exitnodes = (len(bad_set)/len(total_set)) * 100
        country_to_meta[cn] = (percentage_of_bad_exitnodes, len(bad_set), len(total_set))

    with open(parent_path + "geographic_exitnode_perc.json", "w") as ouf:
        json.dump(country_to_meta, fp=ouf)


def make_arr(resolver_ip_to_verdict_list, ttl):
    arr_global = []

    for resolver_ip in resolver_ip_to_verdict_list:
        good_len = len(resolver_ip_to_verdict_list[resolver_ip]["g"])
        bad_len = len(resolver_ip_to_verdict_list[resolver_ip]["b"])
        if good_len + bad_len < 5:
            continue
        all_resolver_global.add(resolver_ip)

        arr_global.append((bad_len / (good_len + bad_len)))

    return arr_global


def cdf_data_maker():
    f = open("dump/mother_info.json")
    d = json.load(f)
    allowed_ttl = [1, 5, 15, 30, 60]
    title_lst = []
    arr_dict = {}

    for ttl in allowed_ttl:
        p = d[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        arr_dict[ttl] = make_arr(p, ttl)
    with open("cdf_data.json", "w") as ouf:
        json.dump(arr_dict, fp=ouf)


all_resolver_global = set()
all_asn_global = set()
all_exitnode_global = set()


all_resolver_global_free = set()
all_asn_global_free = set()
all_exitnode_global_free = set()


all_considered_resolvers = set()
all_public_resolvers = set()
all_local_resolvers = set()

ttl_to_arr = {}

is_local = defaultdict(lambda : False)

all_cn = set()
bad_cn = set()

all_asn = set()
bad_asn = set()

overlapping_resolvers = set()

one_count = 0
zero_count = 0


preprocess_resolvers()

