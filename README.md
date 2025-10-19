# Linux_Security_Tools_Suite

Linux資安工具整合

---

## 開始之前請先下載 `PyQt5` 、 `sshpass` 、 `其他所有套件`

> PyQt5
將以下文字貼入 Windows PowerShell 中使用  
 ``` pip install PyQt5 ```

> sshpass
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install sshpass ```

直接開啟.exe執行檔即可使用  
執行檔位置於: /Linux_Security_Tools_Suite/dist/Linux_Security_Tools_Suite.exe

此執行檔對於新手初期接觸Linux以及資安方面的指令可以有較快的上手時間  
將常用的15~20項功能以GUI(圖形介面)的形式供選用

> 功能介紹
- 系統資訊: 顯示當前使用者
- 檔案列表: 列出指定位置的所有資料 (可搭配 -l -a ...)
- 內容查看: 列出指定檔案的內容 (可使用自適應檔案解碼)
- IP狀態查詢: 檢測與對方電腦的連線狀態、延遲，可使用 `範圍 IP` 以及 `查看特定 Port`
- 傳輸測試: 可連接到其他設備並接收或發送訊息
- 網路掃描: 強大的掃描工具，可掃目標IP的所有Port口情況 (Open or Close)
- 路由追蹤: 可檢測本機到對方IP中間經過了那些設備，以及中間每台設備的延遲
- DNS查詢: 查詢DNS、IP、Domain
- 網頁請求: HTTP(S)客戶端，可查詢HTML、HEADER ....等
- 暴力破解: 強大的暴力破解工具，可使用SSH、FTP、http(s)-get、http(S)-post-form
- SSH連線: 可使用IP位址搭配帳號密碼以command line方式遠端連線

> 暴力破解 http-post-form
- HTTP PATH: 要破解的網站當前分頁 `Ex: 192.168.1.1/login.html` 就輸入 `/login.html`
- User field: 找尋當前網頁Source Code `User` 欄位的 `ID` 並填入
- Pass field: 找尋當前網頁Source Code `Password` 欄位的 `ID` 並填入
- Failure string: 填入當帳號密碼錯誤的時候會顯示的錯誤代碼 (請整行填入)