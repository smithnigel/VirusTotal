import sys
import hashlib
from os import path
from random import sample
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi

api_key = "" # Insert API Key here
vt = VirusTotalPublicApi(api_key)

def upload_to_vt(file):
    with open(file, "rb") as f:
        malware_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"\x1b[94m[MD5 Hash]: \x1b[0m" + f"\x1b[92m{malware_md5}\x1b[0m")
        response = vt.get_file_report(malware_md5)
        rsp_code = (response['results'])['response_code']
        if rsp_code == 0:
            if path.getsize(file) > 32000000:
                print("\x1b[91m Filesize limit of 32mb exceeded\x1b[0m")
                exit()
            else:
                file_response = vt.scan_file(f, from_disk=False)
                rsp_type = "file"
                return file_response, rsp_type
        else:
            rsp_type = "lookup"
            return response, rsp_type

def get_names(scans_dict):
    names = []
    for scans in scans_dict.keys():
        vals = scans_dict[scans]
        if vals['detected'] is True:
            names.append(vals['result'])
    return sample(names, 5)
def display(rsp_dict, rsp_type):
    results = rsp_dict['results']
    if rsp_type == 'file':
        print("\x1b[94m[----- Results -----]\x1b[0m")
        print(f"\x1b[94mResponse: \x1b[0m" + f"\x1b[92m{results['verbose_msg']}\x1b[0m")
        print(f"\x1b[94mLink to scan: \x1b[0m" + f"\x1b[92m{results['permalink']}\x1b[0m")
        print("\x1b[94m[-------------------]\x1b[0m")
    else:
        scans = results['scans']
        names = get_names(scans)
        print("\x1b[94m[----- Results -----]\x1b[0m")
        print(f"\x1b[94m[Total Results]: \x1b[0m" + f"\x1b[92m{results['total']}\x1b[0m")
        print(f"\x1b[94m[Percentage Flagged]: \x1b[0m" + f"\x1b[92m{100 * float(results['positives']) // float(results['total'])}%\x1b[0m")
        print(f"\x1b[94m[Known as]: \x1b[0m\x1b[92m", end = '', flush=True)
        print(*names, sep=', ', end='\x1b[0m\n')
        print(f"\x1b[94m[Link To Scan]: \x1b[0m" + f"\x1b[92m{results['permalink']}\x1b[0m")
        print("\x1b[94m[-------------------]\x1b[0m")
def main(filename):
    rsp, rsp_type = upload_to_vt(filename)
    display(rsp, rsp_type)


if __name__ == "__main__":
    try:
        start = datetime.now()
        main(sys.argv[1])
        finish = datetime.now()
        print(f"Runtime: {finish - start}")
    except IndexError:
        print(f"Usage: {sys.argv[0]} <filename>")