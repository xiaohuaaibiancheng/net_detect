import os
import uuid

# 使用UUID生成唯一文件名
out = uuid.uuid4()
unique_pcap_file = f"output_{out}.pcap"
unique_csv_file = f"output_{out}.pcap_Flow.csv"

# 定义基本目录为当前工作目录下的 "temp" 文件夹
inital_path=os.getcwd()
base_dir = "CICFlowMeter-4.0/bin/temp"
mid_dir="temp"
bin_path="CICFlowMeter-4.0/bin"
# 使用相对路径
temp_output_pcap = os.path.join(base_dir, "pcap", "temp_wlan_capture.pcap")
final_output_pcap = os.path.join(base_dir, "pcap", unique_pcap_file)
pcap_to_csv=os.path.join(mid_dir, "pcap", unique_pcap_file)
csv_path = os.path.join(mid_dir, "csv")
output_file_path = os.path.join(csv_path, unique_csv_file)

# 假设 CICFlowMeter-4.0 文件夹位于当前工作目录
CSV_FILE = 'users.csv'
tshark_path=r"D:\Wireshark\tshark.exe"
cfm_path = os.path.join("CICFlowMeter-4.0", "bin")  # 更新为cfm.bat的实际相对路径

# 确保输出目录存在
os.makedirs(os.path.dirname(temp_output_pcap), exist_ok=True)
os.makedirs(csv_path, exist_ok=True)