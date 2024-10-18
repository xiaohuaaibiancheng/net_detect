from waitress import serve
import app  # 这是你的Flask应用模块名

from pyngrok import ngrok
#ngork 的令牌
ngrok.set_auth_token("2hU4XriCqvrxEcKNd2CONf6YwWj_7SHYdPt5L51x7ivEndLU1") #这里设置你的ngrok的token

# 启动Ngrok隧道
ngrok_tunnel = ngrok.connect(8080)
public_url = ngrok_tunnel.public_url
print(f" * Ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:8080\"")

# 将URL保存到文件中
with open("ngrok_url.txt", "w", encoding="utf-8") as url_file:
    url_file.write(public_url)

# 使用Waitress来服务Flask应用
serve(app.app, host='0.0.0.0', port=8080)