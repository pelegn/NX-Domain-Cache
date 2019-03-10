import re
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta
import json
import ast
from ripe.atlas.cousteau import (
    AtlasResultsRequest)
from ripe.atlas.sagan import  DnsResult
from ripe.atlas.cousteau import (
  Dns,
  AtlasSource,
  AtlasCreateRequest
)
from incf.countryutils import transformations
import requests
import plotly.plotly as py
import pandas as pd
from matplotlib import pyplot
import numpy as np


def print_measurement(source):
    print source
    response = requests.get(source).json
    my_response = response.im_self.content
    my_result_dict = json.loads(my_response)
    parsed_dict = {}
    for meas in my_result_dict:
        my_result = DnsResult(meas)
        # my_result = Result.get(response)

        print str(my_result)
        if not my_result["probe_id"] in parsed_dict:
            parsed_dict[my_result["probe_id"]] = my_result["responses"]
        else:
            print str(my_result["probe_id"]) + " not suppose to be duplicate"
        # for i, var in enumerate(my_result.responses):
        #     if 'ANCOUNT' in var.raw_data:
        #         print "ANCount " + str(i) + ":" + str(var.raw_data['ANCOUNT'])
        #     elif 'result' in var.raw_data and 'ANCOUNT' in var.raw_data['result']:
        #         print "ANCount_" + str(i) + ":" + str(var.raw_data['result']['ANCOUNT'])
    print "finished parsing"

def printMeas2(msm_id):
    kwargs = {
        "msm_id": msm_id
    }
    probe_ids = [6371, 10061, 10145, 35439]

    is_success, results = AtlasResultsRequest(**kwargs).create()

    if is_success:
        for result in results:
            print result["prb_id"]
            if result["prb_id"] in probe_ids:
                print "found one"
            if 'resultset' in result:
                for i, var in enumerate(result['resultset']):
                    if 'result' in var:
                        if 'ANCOUNT' in var['result']:
                            print "ANCount " + str(i) + ":" + str(var['result']['ANCOUNT'])
                            print "ARCount " + str(i) + ":" + str(var['result']['ARCOUNT'])
            else:
                print "ANCount " + ":" + str(result['result']['ANCOUNT'])
        print(results)
def createMeasurment(measId, probe_list, start_time):
    ATLAS_API_KEY = "d4974388-953d-48ea-8858-41a58f6202e8"
    stop = start_time + timedelta(minutes=10)
    desc = "measurment_{}".format(measId)
    dnsreq = Dns(
        ** {"af": 4,
            "description": desc,
            "query_type": "A",
            "query_class": "IN",
            "query_argument": "www.probe_$p.iotsecproject.tech",
            "use_macros": "true",
            "use_probe_resolver": "true",
            "interval": 300,
            "start": str(start_time),
            "stop": str(stop)
            })

    source = AtlasSource(value=str(probe_list)[1:-1], type="probes",  requested=len(probe_list))

    atlas_request = AtlasCreateRequest(
        start_time=start_time,
        stop_time=stop,
        key=ATLAS_API_KEY,
        measurements=[dnsreq],
        sources=[source]
    )
    (is_success, response) = atlas_request.create()
    print is_success
    print response
    with open(r'C:\Users\pelegn\Documents\Private\School\Networking\final project\Measurment_Ids.txt', "a") as myfile:
        myfile.write(str(response) + "\n")

def analyze(tcpdump):
    # kwargs = {
    #     "msm_id": meas_id
    # }
    # is_success, results = AtlasResultsRequest(**kwargs).create()

    with open(tcpdump)as tcpfile:
        content = tcpfile.readlines()
        probe_dict = defaultdict(lambda: [0])
        double_req_array = []
        for line in content:
            lower_line = line.lower()
            if "a? www.probe" in lower_line:
                match = re.search('probe_(\d+)', lower_line)
                if match:
                    probe_id = match.group(1)
                    curr = probe_dict[probe_id]
                    time = datetime.strptime(lower_line.split(" ")[0], "%H:%M:%S.%f")
                    curr[0] += 1
                    curr.append(time)
                    for i in range(1, len(curr)):
                        if abs(time - curr[i]) > timedelta(minutes=1) and probe_id not in double_req_array:
                            double_req_array.append(probe_id)
                    probe_dict[match.group(1)] = curr
    print sorted(double_req_array)
    print "number of double req:{}".format(len(double_req_array))
    return double_req_array

    #
    # if is_success:
    #     for result in results:
    #         print result["prb_id"]
    #         if 'resultset' in result:
    #             for i, var in enumerate(result['resultset']):
    #                 if 'result' in var:
    #                     if 'ANCOUNT' in var['result']:
    #                         print "ANCount " + str(i) + ":" + str(var['result']['ANCOUNT'])
    #                         print "ARCount " + str(i) + ":" + str(var['result']['ARCOUNT'])
    #         else:
    #             print "ANCount " + ":" + str(result['result']['ANCOUNT'])
    #     print(results)

def create_probe_list():
    global ids, f
    payload = {'fields': ['id', 'status', 'is_public', 'country_code']}
    r = requests.get('https://atlas.ripe.net/api/v2/probes/')
    res = r.json()
    ids = []
    while res.get('next'):
        for probe_res in res['results']:
            status = probe_res.get('status')
            is_public = probe_res.get('is_public')
            if is_public:
                ids.append((probe_res['id'], probe_res['country_code']))
        r = requests.get(res['next'])
        res = r.json()
    with open(r'C:\Users\pelegn\Documents\Private\School\Networking\final project\full_probes.txt', "w") as f:
        f.write(str(ids))


def create_country_histogram(double_free_dict, probe_dict):
    histogarm = defaultdict(lambda: [0])
    continentHistogram = defaultdict(int)
    dropCount = 0
    for item in double_free_dict.items():
        if item[1] < 2:
            dropCount += 1
            continue
        if int(item[0]) in probe_dict:
            country = probe_dict[int(item[0])]
            tmp = histogarm[country]
            tmp[0] += 1
            histogarm[country] = tmp
        else:
            dropCount += 1
    print "DropCount:{}".format(dropCount)
    for entry in histogarm.items():
        try:
            continent = transformations.cca_to_ctn(entry[0])
            continentHistogram[continent] += entry[1][0]
        except:
            pass

    return histogarm, continentHistogram


def load_probe_list():
    with open(r'C:\Users\pelegn\Documents\Private\School\Networking\final project\probes.txt', "r") as f:
        line = f.readlines()
    ids = ast.literal_eval(line[0])
    probe_dict = {}
    for id in ids:
        if not id[1]:
            continue
        try:
            probe_dict[id[0]] = transformations.ccn_to_cca3(transformations.cca2_to_ccn(id[1].lower()))
        except:
            pass
    return ids, probe_dict


def create_ripe_measurments(ids):
    start_time = datetime.utcnow() + timedelta(minutes=5)
    probe_list = []
    times = []
    batchSize = 1000
    for currMeasId in range(len(ids) / batchSize + 1):
        times.append(start_time + timedelta(minutes=10 * currMeasId))
        probe_list.append([x[0] for x in ids[currMeasId * batchSize: (currMeasId + 1) * batchSize]])
    for currMeasId in range(len(ids) / batchSize + 1):
        pass
        # createMeasurment(currMeasId, probe_list[currMeasId], times[currMeasId])


def analyze_measurment_results():
    double_free_dict = defaultdict(int)
    for i in range(1, 4):
        l = analyze(r'C:\Users\pelegn\Documents\Private\School\Networking\final project\test{}_dump'.format(i))
        for item in l:
            double_free_dict[item] += 1
    return double_free_dict


def show_continent_histogram(all_probe_continent_histo, no_cache_histo):
    continents = all_probe_continent_histo.keys()
    y_pos = np.arange(len(continents))
    allContinentCount = all_probe_continent_histo.values()
    no_cache_count = no_cache_histo.values()
    _, ax = pyplot.subplots()
    ax.bar(y_pos, allContinentCount, align='center', alpha=0.5, label='Total probes')
    ax.bar(y_pos, no_cache_count, align='center', alpha=0.7, label='No Caching NX-Domain')
    pyplot.xticks(y_pos, continents, rotation='vertical')
    pyplot.ylabel('# of probes in continent')
    pyplot.title('Number of Probes that didn\'t have resolver NX-Domain Caching by Continents')
    # Create labels
    label = []
    for i in range(len(continents)):
        label.append('{0:.2f} %'.format(100 * (float(no_cache_count[i]) / float(allContinentCount[i]))))
    for i, v in enumerate(no_cache_count):
        ax.text(i - 0.1, v + 3, label[i], color='black', fontweight='bold')
    pyplot.legend()
    pyplot.show()
    return


def show_heat_map(no_cache_country_histo):
    df = pd.DataFrame(list(no_cache_country_histo.iteritems()), columns=['Code', 'Value'])
    data = [dict(
        type='choropleth',
        locations=df['Code'],
        z=df['Value'],
        text=df['Code'],
        colorscale=[[0, "rgb(5, 10, 172)"], [0.35, "rgb(40, 60, 190)"], [0.5, "rgb(70, 100, 245)"], \
                    [0.6, "rgb(90, 120, 245)"], [0.7, "rgb(106, 137, 247)"], [1, "rgb(220, 220, 220)"]],
        autocolorscale=False,
        reversescale=True,
        marker=dict(
            line=dict(
                color='rgb(180,180,180)',
                width=0.5
            )),
        colorbar=dict(
            autotick=False,
            tickprefix='',
            title='# of non caching probes'),
    )]
    layout = dict(
        title='Heat Map \nNumber of probes that their resolver did not cache NX-Domains',
        geo=dict(
            showframe=False,
            showcoastlines=False,
            projection=dict(
                type='Mercator'
            )
        )
    )
    fig = dict(data=data, layout=layout)
    py.plot(fig, validate=False, filename='d3-world-map')

def print_country_no_cache_percentage(all_probe_country_histo, no_cache_country_histo):
    print "No NX-Domain caching percentage by Country:"
    percentList = []
    for item in no_cache_country_histo.items():
        percentList.append((item[1][0], all_probe_country_histo[item[0]][0], item[0]))

    for item in sorted(percentList, reverse=True):
        print '{0}: {1} / {2}'.format(transformations.cc_to_con(item[2]), item[0], item[1])


if __name__ == '__main__':
    bCreateProbeList = False
    bCreateMeasurments = False

    if bCreateProbeList:
        create_probe_list()

    ids, probe_dict = load_probe_list()
    if bCreateMeasurments:
        create_ripe_measurments(ids)

    double_free_dict = analyze_measurment_results()

    all_probe_country_histo, all_probe_continent_histo = create_country_histogram(probe_dict, probe_dict)
    no_cache_country_histo, no_cache_continent_histo = create_country_histogram(double_free_dict, probe_dict)
    print_country_no_cache_percentage(all_probe_country_histo, no_cache_country_histo)

    show_continent_histogram(all_probe_continent_histo, no_cache_continent_histo)

    show_heat_map(no_cache_country_histo)
