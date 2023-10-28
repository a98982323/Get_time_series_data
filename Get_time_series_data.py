from scapy.all import *
from scapy.layers.inet import IP

import numpy as np
from collections import Counter
import matplotlib.pyplot as plt
import pandas as pd
import os

# Entropy specific for ip addresses in dict format
from math import log2
from scipy.special import gamma

# Entropy
def calculate_entropy(data_dict):
    total_count = sum(data_dict.values())
    if total_count == 0:
        return 0.0  # Avoid division by zero
    
    probabilities = [count / total_count for count in data_dict.values()]
    
    entropy = -sum(p * log2(p) for p in probabilities if p > 0)
    # normalize entropy
    entropy /= log2(total_count)
    return entropy

# Weibull parameters
def calculate_weibeull_paramter(data_dict):
    ip_f0_values = np.array(len(list(data_dict.keys())))
    ip_f1_values = np.array(sum(data_dict.values()))
    ip_f2_values = np.array(sum([count ** 2 for count in list(data_dict.values())]))
   
    # formula
    ip_M2 = ip_f2_values / ip_f0_values
    ip_M1 = ip_f1_values / ip_f0_values
    ip_freqm_est_mean = ip_M1
    ip_freqm_est_var = ip_M2 - ip_M1**2
    ip_weibull_k = (ip_freqm_est_mean / (ip_freqm_est_var)**0.5) ** (1.086)
    ip_weibull_theta = ip_freqm_est_mean / gamma(1 + 1 / ip_weibull_k)
    return ip_weibull_k, ip_weibull_theta



IP.payload_guess = []  # speed up, we don't need payload info
pkt_pcap = PcapReader('./trace/Merged_MAWI19040918+CAIDAdual_oneway.pcap')
pkt_pcap_filename = pkt_pcap.filename.split('/')[-1].split('.')[0]

sip_ct = Counter()
dip_ct = Counter()
sip_pkt_size_ct = Counter()
dip_pkt_size_ct = Counter()
# Basic features
total_packet_count = 0
total_packet_size = 0 
# F0, F1, F2 values
sip_F0_values, sip_F1_values, sip_F2_values = [], [], []
dip_F0_values, dip_F1_values, dip_F2_values = [], [], []
# Statistical values
sip_raw_mean, sip_raw_std, sip_raw_skew, sip_raw_kurtosis = [], [], [], []
# Entropy values
entropy_sip, entropy_dip = [], []
# Weibull parameters
sip_weibull_k, sip_weibull_theta = [], []
dip_weibull_k, dip_weibull_theta = [], []

time_interval = 1.0 # second
start_time = None
pkt_index = 0
for pkt in pkt_pcap:
    if pkt_index == 0:
        start_time = pkt.time
    current_time = pkt.time
    pkt_index += 1
    if IP in pkt:
        sip_ct.update([pkt[IP].src])
        dip_ct.update([pkt[IP].dst])
        sip_pkt_size_ct.update({pkt[IP].src: pkt[IP].len})
        dip_pkt_size_ct.update({pkt[IP].dst: pkt[IP].len})
        total_packet_count += 1
        #total_packet_size += pkt[IP].len
        if (current_time-start_time) >= time_interval:
            # store path
            path = './results/{}/{}s'.format(pkt_pcap_filename, time_interval)
            os.makedirs(path, exist_ok=True)
            
            
            sip_df = pd.concat([pd.DataFrame.from_dict(sip_ct, orient='index', columns=['sip_ct']),
                    pd.DataFrame.from_dict(sip_pkt_size_ct, orient='index', columns=['sip_pkt_size_ct'])], axis=1)
            sip_df.to_csv(path_or_buf=path+'/{}_sip.csv'.format(current_time), index=True)
            
            dip_df = pd.concat([pd.DataFrame.from_dict(dip_ct, orient='index', columns=['dip_ct']),
                    pd.DataFrame.from_dict(dip_pkt_size_ct, orient='index', columns=['dip_pkt_size_ct'])], axis=1)
            dip_df.to_csv(path_or_buf=path+'/{}_dip.csv'.format(current_time), index=True)
            # Entropy
            entropy_sip.append(calculate_entropy(sip_ct))
            entropy_dip.append(calculate_entropy(dip_ct))
            # F0, F1, F2 values
            ## src
            sip_F0_values.append(len(sip_ct.keys()))
            sip_F1_values.append(sum(sip_ct.values()))
            sip_F2_values.append(sum([count**2 for count in sip_ct.values()]))
            ## dst
            dip_F0_values.append(len(dip_ct.keys()))
            dip_F1_values.append(sum(dip_ct.values()))
            dip_F2_values.append(sum([count**2 for count in dip_ct.values()]))
            # Weibull parameters
            sip_weibull_k, sip_weibull_theta = calculate_weibeull_paramter(sip_ct)
            dip_weibull_k, dip_weibull_theta = calculate_weibeull_paramter(dip_ct)
            # Reset
            sip_ct, dip_ct = Counter(), Counter()
            sip_pkt_size_ct, dip_pkt_size_ct = Counter(), Counter()
            sip_df, dip_df = None, None
            start_time = current_time

# Dump total feature
path = './results/{}/{}s'.format(pkt_pcap_filename, time_interval)
os.makedirs(path, exist_ok=True)

osip_df = pd.DataFrame({'sip_F0': sip_F0_values,
                        'sip_F1': sip_F1_values,
                        'sip_F2': sip_F2_values,
                        'sip_entropy': entropy_sip,
                        'sip_weibull_k': sip_weibull_k,
                        'sip_weibull_theta': sip_weibull_theta})
osip_df.to_csv(path_or_buf=path+'total_sip_features.csv', index=False)
odip_df = pd.DataFrame({'dip_F0': dip_F0_values,   
                        'dip_F1': dip_F1_values,
                        'dip_F2': dip_F2_values,
                        'dip_entropy': entropy_dip,
                        'dip_weibull_k': dip_weibull_k,
                        'dip_weibull_theta': dip_weibull_theta})
odip_df.to_csv(path_or_buf=path+'/total_dip_features.csv', index=False)
