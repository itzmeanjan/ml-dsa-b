#!/usr/bin/python

import json
import sys
import typing

ML_DSA_44_ACVP_KAT_FILE_NAME="ml_dsa_44_b_sig-gen.kat"
ML_DSA_65_ACVP_KAT_FILE_NAME="ml_dsa_65_b_sig-gen.kat"
ML_DSA_87_ACVP_KAT_FILE_NAME="ml_dsa_87_b_sig-gen.kat"

def extract_and_write_ml_dsa_sign_kats(test_groups: list[dict[str, typing.Any]], write_to_file: str):
    with open(write_to_file, "wt") as fd:
        for test_group in test_groups:

            for test in test_group["tests"]:
                fd.write(f'skey = {test["sk"]}\n')
                fd.write(f'msg = {test["message"]}\n')
                fd.write(f'rnd = {test["rnd"]}\n')
                fd.write(f'sig = {test["signature"]}\n')
                fd.write('\n')

        fd.flush()


def main():
    json_as_str = ''
    for line in sys.stdin:
        json_as_str += line
    
    acvp_kats = json.loads(json_as_str)

    ml_dsa_44_param_set = [acvp_kats["testGroups"][0], acvp_kats["testGroups"][1]]
    ml_dsa_65_param_set = [acvp_kats["testGroups"][2], acvp_kats["testGroups"][3]]
    ml_dsa_87_param_set = [acvp_kats["testGroups"][4], acvp_kats["testGroups"][5]]

    extract_and_write_ml_dsa_sign_kats(ml_dsa_44_param_set, ML_DSA_44_ACVP_KAT_FILE_NAME)
    extract_and_write_ml_dsa_sign_kats(ml_dsa_65_param_set, ML_DSA_65_ACVP_KAT_FILE_NAME)
    extract_and_write_ml_dsa_sign_kats(ml_dsa_87_param_set, ML_DSA_87_ACVP_KAT_FILE_NAME)


if __name__=='__main__':
    main()
