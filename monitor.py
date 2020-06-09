import psutil
import time
import datetime
import os
import ctypes
import threading

vmware_process_list = ["vmware.exe", "vmware-authd.exe", "vmware-usbarbitrator64.exe", "vmware-usbarbitrator.exe",
                       "vmnat.exe", "vmnetdhcp.exe",
                       "vmware-unity-helper.exe", "vmware-hostd.exe", "vmware-unity-helper.exe",
                       "vmware-tray.exe", "vmx.exe"]

vbox_process_list = ["vboxsvc.exe", "virtualbox.exe", "virtualboxvm.exe"]
target = vmware_process_list + vbox_process_list
# common_target_process = ["cmd.exe", "powershell.exe", "mstsc.exe"]
logging = True


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def to_dict(x):
    di = x.as_dict(attrs=['pid', 'name', 'username', "exe", "ppid"])
    di["createtime"] = datetime.datetime.fromtimestamp(x.create_time()).strftime("%H:%M:%S")
    return di


def print_proc_info(proc, is_parent=False):
    c = " "
    if not proc.is_running():
        c = "-"
    if is_parent:
        c = "→"
    i = total_dict[proc]
    print(
        f"{c}{i['pid']:<6} {i['name']:<27} {i['ppid']:<5} {i['username'] or '':20} {i['createtime']:9} {i['exe']}")


def load_proc_file(name="allowed_procs.txt"):
    res = []
    if os.path.isfile(name):
        with open(name, "r") as f:
            res = f.read().splitlines()
        print(f"loaded list of allowed process: {', '.join(res)}")
    return res


def log(text):
    print(text)
    if logging:
        with open("monitor.log", "a+") as f:
            f.write(text)


# import queue
# que = queue.Queue()
# def alert(info):
#     thr = threading.Thread(
#         target=lambda: ctypes.windll.user32.MessageBoxW(0, "text", "title", 48)
#     )
#     thr.start()
#     # thr.res
#     thr.join()
#     result = que.get()
#     print(result)
#     que.task_done()
# alert("1")
# quit()
# import queue
# que = queue.Queue()
def alert(lst):
    def allow_process(proc_lst):
        with open("allowed_procs.txt", "a+") as f:
            for p in proc_lst:
                f.write(p + "\n")
        global allowed_procs
        allowed_procs += proc_lst
        log(f"process name '{', '.join(proc_lst)}' added to white list")

    def msg_box(lst):
        info = ""
        proc_name = []
        for i in lst:
            info += f" pid:{i['pid']} name:{i['name']} ppid:{i['ppid']} username:{i['username'] or ''} time:{i['createtime']} exe:{i['exe']} cmd:{i['cmdline']}\n"
            proc_name.append(i["name"])
        text = f"Your VM has created an unusual process:\n{info}\npress \"OK\" button to add [{' '.join(proc_name)}] to white list"
        log(f"Suspicious:\n{info}")
        res = ctypes.windll.user32.MessageBoxW(0, text, "Suspicious VM activity", 49)
        if res == 1:  # ok pressed
            allow_process(proc_name)
        else:
            log("  IGNORED BY USER")

    threading.Thread(target=msg_box, args=(lst,)).start()


def process_analysis(proc):
    lst = []
    print("here")
    try:
        # if proc.name() not in target:  # suspicious process
        #     print("now in target", proc["name"])
        for child_proc in proc.children(recursive=True):
            if child_proc.name() not in target + allowed_procs:
                p = to_dict(child_proc)
                p["cmdline"] = "".join(child_proc.cmdline())
                lst.append(p)
    except psutil.NoSuchProcess:
        pass
    finally:
        if lst:
            alert(lst)


# a = psutil.Process(308)
# process_analysis(a)
# print("1END")
# quit()
target = ['notepad.exe']
if __name__ == '__main__':
    parent_children = dict()
    total_dict = dict()
    allowed_procs = load_proc_file()
    print(allowed_procs, "asd")
    while True:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in target:
                # if proc.info['name'].lower()[:4] == target or proc.info['name'].lower() == "virtualbox.exe":
                if proc not in total_dict:
                    total_dict[proc] = to_dict(proc)
                    parent_children[proc] = []
                need_analyse = False
                for p in proc.children(recursive=True):
                    if p not in total_dict:
                        total_dict[p] = to_dict(p)
                        if proc in parent_children:
                            parent_children[proc].append(p)
                        else:
                            parent_children[proc] = [p]
                        print('new proc', p)
                        if total_dict[p]["name"] not in allowed_procs + target:
                            need_analyse = True
                if need_analyse:
                    process_analysis(proc)
        # clear()
        # print(f" {'pid':<6} {'name':<27} {'ppid':<5} {'username':20} {'time':9} {'exe'}")
        # for proc in parent_children:
        #     print_proc_info(proc, True)
        #     for child in parent_children[proc]:
        #         print_proc_info(child)
        time.sleep(0.2)
