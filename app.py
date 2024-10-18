import datetime
import io
import time
import os

from typing import Tuple
import pandas as pd
from flask import Flask, request, render_template, jsonify, session, url_for, redirect, send_file, make_response
from matplotlib import pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, Spacer, SimpleDocTemplate
from scapy.all import rdpcap, wrpcap


from openAPI import OpenAPISample
from tool import load_and_preprocess_data, create_single_sequence, predict, get_most_common_label, \
    plot_to_img_tag, process_df_csv, model, scaler, sequence_length, start_packet_capture, convert_pcap_to_csv, \
    plot_sequence_data, plot_prediction_distribution, extract_ip_features, get_access_token_and_call_api, \
    extract_unique_ips, read_users, write_user, send_QQ_email_plain
from path import temp_output_pcap, final_output_pcap, csv_path, cfm_path, output_file_path, pcap_to_csv, inital_path,bin_path
import seaborn as sns
from datetime import datetime


app = Flask(__name__)
app.secret_key = os.urandom(24)
os.environ['WLAN_INTERFACE'] = 'WLAN' #默认抓取的为WLAN
START_TIME = None
# 注册中文字体

@app.route('/')
def logined():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        users = read_users()

        if not users:  # Check if users is empty
            return jsonify({'message': '查无此账号，请先注册','redirect': url_for('registered')}),200

        if username in users and users[username]['password'] == password:
            session['username'] = username
            return jsonify({'message': '登录成功！', 'redirect': url_for('home')}), 200
        else:
            return jsonify({'message': '用户名或密码错误！'}), 401

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        print(data)
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        users = read_users()


        if username in users:
            return jsonify({'message': '用户名已存在！'}), 400
        else:
            write_user(username, password, email)
            return jsonify({'message': '注册成功，请登录！', 'redirect': url_for('login')}), 200

    return render_template('register.html')
@app.route('/registered')
def registered():
    return render_template('register.html')
@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/table')
def table_page():
    return render_template('table.html')

@app.route('/echarts')
def echarts_page():
    return render_template('echarts.html')
@app.route('/button')
def button_page() -> str:
    """
    Render the button page.
    """
    return render_template('button.html')

@app.route('/start_collection', methods=['POST'])
def start_collection() -> Tuple[str, int]:
    """
    Start the data collection process.
    """
    global start_time
    start_time = time.time()
    return jsonify({'status': 'collection started'}), 200


@app.route('/stop_collection', methods=['POST'])
def stop_collection() -> Tuple[str, int]:
    """
    停止数据采集过程
    """
    global start_time
    if start_time is None:
        return jsonify({'status': 'error', 'message': 'Collection not started'}), 400
    else:
        end_time = time.time()
        duration = end_time - start_time
        start_time = None
    if duration <15:
        raise ValueError("收集时间太短，请重新操作！")
    interface = os.getenv('WLAN_INTERFACE')
    if interface is None:
        raise ValueError("环境变量 'WLAN_INTERFACE' 未设置。")

    temp_output_file = temp_output_pcap
    final_output_file =final_output_pcap
    csv_output_path =csv_path
    cfm_bat_path =cfm_path

    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(temp_output_file), exist_ok=True)
        os.makedirs(os.path.dirname(final_output_file), exist_ok=True)
        os.makedirs(csv_output_path, exist_ok=True)
        print(f"Directories checked/created.")

        # Start packet capture
        start_packet_capture(interface, duration, temp_output_file)



        print(f"Temp output file {temp_output_file} exists.")

        # Read and write the packet capture file
        packets = rdpcap(temp_output_file)
        wrpcap(final_output_file, packets)

        print(f"Packets written to {final_output_file}.")

        # Convert PCAP to CSV
        convert_pcap_to_csv(pcap_to_csv, csv_output_path, cfm_bat_path)
        print(f"PCAP to CSV conversion done successfully.")
        message = 'PCAP to CSV conversion done successfully in {}.'.format(duration)
        return jsonify({'status': 'collection stopped', 'message': message}), 200
    except Exception as e:
        app.logger.error(f"Error during stop_collection: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_data', methods=['GET'])
def get_data() -> Tuple[str, int]:
    """
    Read the CSV file and return the data.
    """
    try:
        with open(output_file_path, 'r') as f:
            df = pd.read_csv(f)
        df = process_df_csv(df)
        data_html = df.to_html(classes='table table-bordered table-striped')
        return jsonify({'status': 'success', 'data': data_html}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/plot_data', methods=['GET'])
def plot_data() -> Tuple[str, int]:
    """
    Read the CSV file, plot the data, and return the plot.
    """
    try:
        with open(output_file_path, 'r') as f:
            df = pd.read_csv(f)
        df = process_df_csv(df)

        # 创建数据分布箱线图
        fig_data_dist = plt.figure(figsize=(6, 16))  # 调整图形尺寸适应竖向布局
        sns.boxplot(data=df, orient='h')  # 设置箱线图为横向
        plt.title('Feature Distribution')
        img_tag= plot_to_img_tag(fig_data_dist)

        return jsonify({'status': 'success', 'img': img_tag}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/most_common_label', methods=['POST'])
def most_common_label() -> Tuple[str, int]:
    """
    Predict the most common label from the uploaded file.
    """
    global common_label
    global label_counts
    filepath=output_file_path

    try:
        features = load_and_preprocess_data(filepath, scaler)
        single_sample = create_single_sequence(features, sequence_length)
        predictions = predict(model, single_sample)
        common_label, label_counts = get_most_common_label(predictions)
        return jsonify({'most_common_label': common_label, 'label_counts': label_counts}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_most_label', methods=['POST'])
def get_most_label() -> Tuple[str, int]:
    """
    Predict the most common label from the uploaded file.
    """
    if request.method == 'POST':
        f = request.files['file']
        filename = f.filename
        print(filename)

        # 确保保存文件的目录存在
        upload_dir = r'./temp/upload_csv'
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        filepath = os.path.join(upload_dir, filename)
        f.save(filepath)  # 保存上传的文件

    try:
        features = load_and_preprocess_data(filepath, scaler)
        single_sample = create_single_sequence(features, sequence_length)
        predictions = predict(model, single_sample)
        most_common_label, label_counts = get_most_common_label(predictions)
        return jsonify({'most_common_label': most_common_label, 'label_counts': label_counts}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/plot_sequence_data', methods=['POST'])
def plot_sequence_data_route():
    os.chdir(inital_path)
    os.chdir(bin_path)
    filepath =output_file_path

    features = load_and_preprocess_data(filepath, scaler)
    single_sample = create_single_sequence(features, sequence_length)

    if single_sample is None:
        return jsonify({'error': 'No data provided'}), 400
    img_tag = plot_sequence_data(single_sample)
    return jsonify({'img_tag': img_tag})

@app.route('/plot_prediction_distribution', methods=['POST'])
def plot_prediction_distribution_route():
    os.chdir(inital_path)
    os.chdir(bin_path)
    filepath = output_file_path

    features = load_and_preprocess_data(filepath, scaler)
    single_sample = create_single_sequence(features, sequence_length)
    predictions = predict(model, single_sample)

    if predictions is None:
        return jsonify({'error': 'No data provided'}), 400
    img_tag = plot_prediction_distribution(predictions)
    return jsonify({'img_tag': img_tag})

@app.route('/IPsource')
def IPsouce_page() -> str:
    """
    Render the IPsource page.
    """
    return render_template('IPSource.html')

@app.route('/Net_Flow_IPSource', methods=['POST'])
def net_flow_ip_source():

    os.chdir(inital_path)
    os.chdir(bin_path)
    # 调用提取IP特征的函数
    ip_features_df = extract_ip_features(output_file_path)
    # 将DataFrame转换为HTML表格
    ip_features_html = ip_features_df.to_html(classes='data', index=False)
    return jsonify({'html': ip_features_html})

rendered_html=None
report_data=None
response_text=None


@app.route('/text-panel')
def text_panel_page():
    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    unique_src_ips, unique_dst_ips = extract_unique_ips(output_file_path)
    message_response_text = OpenAPISample.get_messages()
    leak_response_text = OpenAPISample.get_leaks()
    overview=f"本次预测采用新型的神经网络架构，旨在消除数据序列的不确定性和增强预测的准确性。"
    global report_data
    report_data = {
        'date':date,
        'overview':overview,
        'Threat type possibilities':label_counts,
        'source_ip':unique_src_ips,
        'destination_ip':unique_dst_ips,

        'message_response':message_response_text,
        ' leak_response':leak_response_text,
        'attachments':output_file_path # 确保附件路径正确
    }

    # 调用你的API请求函数并获取响应文本

    global rendered_html
    rendered_html = render_template('text-panel.html', report_data=report_data)
    # 将报告HTML和响应文本作为变量传递给模板
    return rendered_html

@app.route('/get-ai-analysis')
def get_ai_analysis():
    # 调用你的API请求函数并获取响应文本
    global response_text
    response_text = get_access_token_and_call_api(report_data)
    # print(response_text)
    return response_text


@app.route('/export-pdf')
def export_pdf():
    os.chdir(inital_path)
    pdfmetrics.registerFont(TTFont('SimSun', 'font/simsun.ttc'))
    global rendered_html
    global report_data
    global response_text

    # 创建PDF
    pdf_io = io.BytesIO()
    doc = SimpleDocTemplate(pdf_io, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    styles['Normal'].fontName = 'SimSun'
    styles['Normal'].fontSize = 12

    elements = []

    # 添加报告数据
    elements.append(Paragraph("报告数据", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"日期: {report_data.get('date', 'N/A')}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"概述: {report_data.get('overview', 'N/A')}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"威胁类型可能性: {report_data.get('Threat type possibilities', 'N/A')}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"源IP: {', '.join(report_data.get('source_ip', []))}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"目标IP: {', '.join(report_data.get('destination_ip', []))}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"消息响应: {report_data.get('message_response', 'N/A')}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"泄漏响应: {report_data.get('leak_response', 'N/A')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # 添加AI分析及建议
    elements.append(Paragraph("AI分析及建议:", styles['Normal']))
    elements.append(Spacer(1, 12))
    for line in response_text.split('\n'):
        elements.append(Paragraph(line, styles['Normal']))
        elements.append(Spacer(1, 12))

    # 构建PDF
    doc.build(elements)

    pdf_io.seek(0)
    return send_file(pdf_io, as_attachment=True, download_name='report.pdf')


@app.route('/send_mail', methods=['POST'])
def send_mail() -> Tuple[str, int]:
    """
    Send warning mail to the user's email when the button is clicked.
    """
    os.chdir(inital_path)
    if 'username' not in session:
        return jsonify({'message': '用户未登录！'}), 401

    username = session.get('username')
    users = read_users()
    if username in users:
        email = users[username]['email']
        print(email)
        if send_QQ_email_plain(email):
            return jsonify({'message': '邮件发送成功！'}), 200
        else:
            return jsonify({'message': '邮件发送失败！'}), 500
    else:
        return jsonify({'message': '邮件发送失败！'}), 500

if __name__ == "__main__":

    app.run(host='0.0.0.0', port=5000, debug=True)
