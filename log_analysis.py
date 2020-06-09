from Evtx.Evtx import Evtx

vmware_process_list = ["vmware.exe", "vmware-authd.exe", "vmware-usbarbitrator64.exe", "vmware-usbarbitrator.exe",
                       "vmnat.exe", "vmnetdhcp.exe",
                       "vmware-unity-helper.exe", "vmware-hostd.exe", "vmware-unity-helper.exe",
                       "vmware-tray.exe", "vmx.exe", "vmware-vmx.exe"]

# vbox_process_list = ["vboxsvc.exe", "virtualbox.exe", "virtualboxvm.exe"]
# target = vmware_process_list + vbox_process_list
target = ["powershell.exe"]
# path = r"%SystemRoot%\System32\Winevt\Logs\Security.evtx"
logging = False
period = 360  # time in seconds
# path = r"D:\check.evtx"


# path = r"D:\test.evtx"
path = r"D:\small_2.evtx"


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def parse_log(path, codes):
    arr = dict()
    with Evtx(path) as log:
        for record in log.records():
            node = record.lxml()
            first_ch = get_child(node, "System")
            event_id = int(get_child(first_ch, "EventID").text)
            if event_id in codes:
                time = get_child(first_ch, "TimeCreated").attrib["SystemTime"]
                EventRecordID = get_child(first_ch, "EventRecordID").text
                event_data = get_child(node, "EventData").getchildren()
                # data = {"EventRecordID": EventRecordID, "TimeStamp": time}
                data = {"TimeStamp": time}
                if event_id == 4688:  # process creation
                    data["Type"] = "Creation"
                    for item in event_data:
                        if item.get("Name") == "NewProcessId":
                            data["NewProcessId"] = int(item.text, 16)
                        elif item.get("Name") == "NewProcessName":
                            data["NewProcessName"] = item.text
                        # elif item.get("Name") == "CommandLine":
                        #     data["CommandLine"] = item.text
                        elif item.get("Name") == "ProcessId":
                            data["ProcessId"] = int(item.text, 16)
                        elif item.get("Name") == "ParentProcessName":
                            data["ProcessName"] = item.text
                        elif item.get("Name") == "TargetUserName":
                            data["TargetUserName"] = item.text
                elif event_id == 4689:  # process termination
                    data["Type"] = "Termination"
                    for item in event_data:
                        if item.get("Name") == "ProcessId":
                            data["ProcessId"] = int(item.text, 16)
                        elif item.get("Name") == "ProcessName":
                            data["ProcessName"] = item.text
                arr[EventRecordID] = data

    return arr


def find_child(eventid):
    index = created.index(eventid)
    res = dict()
    NewProcessId = arr[eventid]["NewProcessId"]
    for id in created[index:]:
        item = arr[id]
        if NewProcessId == item["ProcessId"]:
            res[id] = find_child(id)
    return res


# def find_child(proc):
#     index = arr.index(proc)
#     t = []
#     for item in arr[index:]:
#         if proc["NewProcessId"] == item["ProcessId"]:
#             y = hex(item["NewProcessId"])
#             res = find_child(item)
#             print(y, res)
#             t.append([y, res])
#     return t


# def find_child(proc):
#     index = arr.index(proc)
#     y = hex(proc["ProcessId"])
#
#     result = dict()
#     cur = ""
#     try:
#         for item in arr[index:]:
#             cur = item
#
#             if proc["NewProcessId"] == item["ProcessId"]:
#                 res = find_child(item)
#                 x = hex(item["ProcessId"])
#                 z= hex(item["NewProcessId"])
#                 result[x] = res
#                 result[y] = z
#                 print(x, res)
#                 # if res:
#                 #     result[x] = res
#                 # else:
#                 #     result[x] = z
#         print(y,"res",result)
#     except Exception as e:
#         print(e)
#         print(cur)
#
#     return result


def filter_logs(arr):
    t = ""
    try:
        created_procs = []
        terminated_procs = dict()
        for id, data in arr.items():
            if data["Type"] == "Creation" and data["ProcessName"]:
                # proc_name = item["ProcessName"].split("\\")[-1]
                # if proc_name.lower() in target:
                created_procs.append(id)
            if data["Type"] == "Termination":
                terminated_procs[data["ProcessId"]] = data
        return created_procs, terminated_procs
    except AttributeError:
        print(t)
        quit()


def log(text):
    print(text)
    if logging:
        with open("log_analysis.log", "a+") as f:
            f.write(text+"\n")


def pretty(dictionary):
    def get_dead_time(pid, time_creation):
        x = terminated.get(pid)
        if x:
            try:
                # format = '%Y-%m-%d %H:%M:%S.%f'
                time_termination = x["TimeStamp"]
                # print(time_creation, time_termination)
                # print(time_creation > time_termination)
                # time_termination = datetime.strptime(time_termination, format)
                # time_creation = datetime.strptime(time_creation, format)
                if time_creation < time_termination:
                    return time_termination
            except ValueError:
                pass

    log("Suspicious VM chaid detected::::")
    log(f"{'pid':10} {'name':90} {'Creation Time':30} {'Termination Time':27}")

    def recursion(xxx, c=-1):
        c += 1
        for item in xxx:
            x = arr[item]["ProcessName"]
            y = arr[item]["NewProcessName"]
            time = arr[item]["TimeStamp"]
            pid = arr[item]["NewProcessId"]
            term_time = get_dead_time(pid, time)
            childs = xxx[item]
            log(f"{'-' * c + '|' + str(pid):10} {y:90} {time:30} {term_time or '':27}")
            if childs:
                recursion(childs, c)

    data = arr[list(dictionary.keys())[0]]
    x = data["ProcessName"]
    pid = data["ProcessId"]
    log(f"{str(pid):10} {x:90}")
    recursion(dictionary)


codes = [4688, 4689]

arr = parse_log(path, codes)
arr.update(parse_log(r"D:\small_1.evtx", codes))
created, terminated = filter_logs(arr)
chain = dict()
for proc in created:
    data = arr[proc]
    proc_name = data["ProcessName"].split("\\")[-1]
    if proc_name.lower() in target:
        chain[proc] = find_child(proc)
print(chain)
pretty(chain)
