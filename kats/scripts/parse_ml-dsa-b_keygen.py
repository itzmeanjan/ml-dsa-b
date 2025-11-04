#!/usr/bin/python

import json
import sys
import typing

ML_DSA_B_44_ACVP_KAT_FILE_NAME="ml_dsa_b_44_b_keygen.kat"
ML_DSA_B_65_ACVP_KAT_FILE_NAME="ml_dsa_b_65_b_keygen.kat"
ML_DSA_B_87_ACVP_KAT_FILE_NAME="ml_dsa_b_87_b_keygen.kat"

def extract_and_write_ml_dsa_keygen_kats(test_group: dict[str, typing.Any], write_to_file: str):
    with open(write_to_file, "wt") as fd:
        for test in test_group["tests"]:
            fd.write(f'seed = {test["seed"]}\n')
            fd.write(f'pkey = {test["pk"]}\n')
            fd.write(f'skey = {test["sk"]}\n')

            fd.write('\n')
        
        fd.flush()


def main():
    json_as_str = ''
    for line in sys.stdin:
        json_as_str += line
    
    acvp_kats = json.loads(json_as_str)

    ml_dsa_b_44_param_set = acvp_kats["testGroups"][0]
    ml_dsa_b_65_param_set = acvp_kats["testGroups"][1]
    ml_dsa_b_87_param_set = acvp_kats["testGroups"][2]

    extract_and_write_ml_dsa_keygen_kats(ml_dsa_b_44_param_set, ML_DSA_B_44_ACVP_KAT_FILE_NAME)
    extract_and_write_ml_dsa_keygen_kats(ml_dsa_b_65_param_set, ML_DSA_B_65_ACVP_KAT_FILE_NAME)
    extract_and_write_ml_dsa_keygen_kats(ml_dsa_b_87_param_set, ML_DSA_B_87_ACVP_KAT_FILE_NAME)


if __name__=='__main__':
    main()
