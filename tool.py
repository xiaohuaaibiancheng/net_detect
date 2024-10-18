import asyncio
import csv
import json
import os
import subprocess
from email.utils import formataddr

import joblib
import pyshark
import requests
import torch
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('agg') 
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
from net import LSTM_ResNet
from collections import Counter

from path import CSV_FILE, tshark_path, inital_path

import smtplib
from email.mime.text import MIMEText

# 模型超参数
feature_dim = 77
num_classes = 7
sequence_length = 30
hidden_dim = 50
num_layers = 3
use_attention = True

# 使用设备
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 加载模型
model = LSTM_ResNet(input_dim=feature_dim, hidden_dim=hidden_dim, num_layers=num_layers, num_classes=num_classes,
                    use_attention=use_attention)
model = model.to(device)
model.load_state_dict(torch.load(r'model/model_epoch_13.pt', map_location=device))
model.eval()

# 加载Scaler
scaler = joblib.load('model/scaler.joblib')

#全局变量
label_counts_dict = {}
def load_and_preprocess_data(filepath, scaler):
    data = pd.read_csv(filepath)
    data=process_df_csv(data)
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.dropna(inplace=True)
    features = data.iloc[:, :-1]
    scaled_features = scaler.transform(features)
    return scaled_features


def create_single_sequence(features, sequence_length):
    # 检查features是否为numpy数组
    if not isinstance(features, np.ndarray):
        raise ValueError("Features must be a numpy array.")

    # 检查features是否有至少两个维度
    if features.ndim < 2:
        raise ValueError("Features must have at least two dimensions.")

    # 获取特征数量
    n_features = features.shape[1]

    # 检查窗口长度是否大于features的长度
    if sequence_length > features.shape[0]:
        raise ValueError("收集数据太少，请重新操作！（至少30条数据）")

    # 创建滑动窗口视图
    try:
        sequences = np.lib.stride_tricks.sliding_window_view(features, (sequence_length, n_features))
        sequences = sequences[:, 0, :, :]
        return sequences
    except ValueError as e:
        # 如果发生错误，打印错误信息并返回None或抛出异常
        print(f"Error creating sliding window view: {e}")
        return None


def predict(model, sample):
    sample_tensor = torch.tensor(sample, dtype=torch.float32).to(device)
    with torch.no_grad():
        prediction = model(sample_tensor)
    return prediction

def process_df_csv(df):
    columns_to_delete = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp']

    # 检查并删除存在的列
    df = df.drop(columns=[col for col in columns_to_delete if col in df.columns])


    # 替换DataFrame的列名
    new_column_names = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
       'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
       'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min', 'Label']  # 根据实际情况替换为你的列名列表
    if len(new_column_names) == len(df.columns):
        df.columns = new_column_names
    else:
        raise ValueError("新列名的数量必须与 DataFrame 的列数相同")
    return df


def convert_pcap_to_csv(input_file, output_path, cfm_bat_path):
    #切换到最初目录
    os.chdir(inital_path)
    # 确保输出目录存在
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    # 打印输入文件路径以进行调试
    print(f"Converting file: {input_file}")

    # 切换到 cfm.bat 所在目录

    os.chdir(cfm_bat_path)
    print(f"Changed working directory to: {os.getcwd()}")


    # 构造并调用命令
    print(os.getcwd())
    command = ['cfm.bat', input_file, output_path]
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        print(f"Command output: {result.stdout}")
        print(f"Command error: {result.stderr}")

        # 检查命令执行结果
        if result.returncode != 0:
            raise RuntimeError(f"Error during PCAP to CSV conversion: {result.stderr}")

        print(f"Conversion done successfully for {input_file} to {output_path}")
    except Exception as e:
        print(f"Exception during conversion: {str(e)}")
        raise RuntimeError(f"Error in convert_pcap_to_csv: {str(e)}")


def plot_to_img_tag(fig):
    # 将图像转换为HTML img标签的逻辑
    img_buf = BytesIO()
    fig.savefig(img_buf, format='png')
    img_buf.seek(0)
    img_data = base64.b64encode(img_buf.getvalue()).decode('utf-8')
    plt.close(fig)
    return f'<img src="data:image/png;base64,{img_data}" />'


def plot_data_distribution(data):
    fig = plt.figure(figsize=(16, 6))
    sns.boxplot(data=data)
    plt.xticks(rotation=90)
    plt.title('Feature Distribution')
    return plot_to_img_tag(fig)


def plot_sequence_data(single_sample):
    fig = plt.figure(figsize=(16, 6))
    for i in range(6):  # Assuming num_features = 6
        plt.plot(single_sample[0, :, i], label=f'Feature {i + 1}', linestyle='-', marker='o', linewidth=2)
    plt.title('Sequence Data Example', fontsize=16)
    plt.xlabel('Time Step', fontsize=14)
    plt.ylabel('Feature Value', fontsize=14)
    plt.legend(loc='upper right', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    return plot_to_img_tag(fig)

def plot_prediction_distribution(prediction):
    _, label_counts = get_most_common_label(prediction)
    labels, counts = zip(*label_counts.items())
    fig = plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, counts, color='skyblue', edgecolor='black')
    plt.title('Prediction Distribution', fontsize=16)
    plt.xlabel('Predicted Label', fontsize=14)
    plt.ylabel('Count', fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()

    # Adding value labels on top of the bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.5, int(yval), ha='center', va='bottom', fontsize=12)

    return plot_to_img_tag(fig)





def start_packet_capture(interface, duration, temp_output_file):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print(f"Starting packet capture on interface {interface} for {duration} seconds.")

        capture = pyshark.LiveCapture(interface=interface, output_file=temp_output_file,
                                      tshark_path=tshark_path)
        capture.sniff(timeout=duration)
        capture.close()

        print(f"Packet capture completed. Output file created at {temp_output_file}")
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")
        raise

def extract_ip_features(file_path):
    """
    从CSV文件中提取溯源IP的特征
    """
    df = pd.read_csv(file_path)
    required_features = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration']
    filtered_df = df[required_features]
    return filtered_df
def get_most_common_label(prediction):
    # 定义标签映射关系
    label_mapping = {
        0: "BENIGN",
        1: "Bot",
        2: "DDoS",
        3: "DoS",
        4: "Patator",
        5: "PortScan",
        6: "Web Attack Brute Force"
    }

    # 获取每行最大值的索引，即预测标签
    _, predicted_label = torch.max(prediction, 1)

    # 计算每个标签的出现次数
    label_counts = Counter(predicted_label.cpu().numpy())

    # 获取出现次数最多的标签
    most_common_label = label_counts.most_common(1)[0][0]

    # 转换为字典，确保键和值为基本数据类型，并进行标签映射
    global label_counts_dict
    label_counts_dict = {label_mapping[int(label)]: int(count) for label, count in label_counts.items()}

    # 打印标签计数字典
    print(label_counts_dict)

    # 返回最常见的标签和标签计数字典
    return label_mapping[int(most_common_label)], label_counts_dict
def get_access_token():
    """
    使用 API Key，Secret Key 获取access_token，替换下列示例中的应用API Key、应用Secret Key
    """

    url = "https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=Z1mUNPY0kLWOchgayFh7VaBm&client_secret=4OaQlm3DRPnhPZ4lBC9vD4JV1qzRHx6R"

    payload = json.dumps("")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json().get("access_token")


def get_access_token_and_call_api(report_data):
    url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/ernie-speed-128k?access_token="  + str(get_access_token())

    payload = json.dumps({
        "messages": [
            {
                "role": "user",
                "content":f"请根据以下网络安全分析报告，针对所识别的网络安全威胁，提供详细的分析及相应的防范建议。\n报告概览如下：\n{str(report_data)}"
            }
        ]
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    response_json = response.json()

    result_text = response_json.get("result", "")

    return result_text


def extract_unique_ips(file_path):
    """
    从CSV文件中提取独一无二的源IP和目标IP
    """
    df = pd.read_csv(file_path)

    # 确保'Src IP'和'Dst IP'列存在
    if 'Src IP' not in df or 'Dst IP' not in df:
        raise ValueError("CSV文件中必须包含'Src IP'和'Dst IP'列")

    # 获取唯一的源IP地址
    unique_src_ips = df['Src IP'].drop_duplicates()

    # 获取唯一的目标IP地址
    unique_dst_ips = df['Dst IP'].drop_duplicates()

    # 可选：将唯一IP转换为列表
    unique_src_ips_list = unique_src_ips.tolist()
    unique_dst_ips_list = unique_dst_ips.tolist()

    return unique_src_ips_list, unique_dst_ips_list


def read_users():
    users = {}
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    username, password, email= row
                    users[username] = {'password':password, 'email':email}
    return users

def write_user(username, password, email):
    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([username, password, email])



def send_QQ_email_plain(receiver):


    sender = user = '1733511417@qq.com'  # 发送方的邮箱账号
    passwd = 'vvieyebexwowchca'  # 授权码

    ##    receiver = '2625464350@qq.com'        # 接收方的邮箱账号，不一定是QQ邮箱
    # 纯文本内容
    msg = MIMEText(str(label_counts_dict), 'plain', 'utf-8')
    # From 的内容是有要求的，前面的abc为自己定义的 nickname，如果是ASCII格式，则可以直接写
    msg['From'] = formataddr(('Exception Detection Service', sender))
    msg['To'] = receiver
    msg['Subject'] = 'Prediction Result'  # 点开详情后的标题



    try:
        # 建立 SMTP 、SSL 的连接，连接发送方的邮箱服务器
        smtp = smtplib.SMTP_SSL('smtp.qq.com', 465)

        # 登录发送方的邮箱账号
        smtp.login(user, passwd)

        # 发送邮件 发送方，接收方，发送的内容
        smtp.sendmail(sender, receiver, msg.as_string())
        print('发送成功')
        smtp.quit()

        return True

    except Exception as e:
        print(e)
        return False

