# Linux_Security_Tools_Suite

### Linux資安工具整合

---

- ### 快速開始

開始之前請先下載 WSL、Ubuntu-22.04  
> **WSL**  
將以下文字貼入 Windows PowerShell 中使用  
```wsl --install``` *需重啟

> **Ubuntu-22.04**  
將以下文字貼入 Windows PowerShell 中使用  
```wsl --install -d Ubuntu-22.04```

> **安裝套件**  
使用 `run.bat` 下載所需的所有工具以及套件 或 使用以下方式手動下載更新工具套件

---

- ### 手動下載更新工具套件

> **Python3**  
將以下文字貼入 Windows PowerShell 中使用  
``` winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements ```

> **PyQt5**   
將以下文字貼入 Windows PowerShell 中使用  
 ``` py -3.12 -m pip install PyQt5 ```

> **WhatWeb**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install whatweb ```

> **Nmap**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install nmap ```

> **Hydra**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install hydra ```

> **Sshpass**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install sshpass ```

> **Gobuster**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install gobuster ```

> **Exiftool**  
將以下文字貼入 WSL bash 中使用  
 ``` sudo apt install exiftool ```

直接開啟.exe執行檔即可使用  
執行檔位置於: `/Linux_Security_Tools_Suite/dist/Linux_Security_Tools_Suite.exe`

此執行檔對於新手初期接觸Linux以及資安方面的指令可以有較快的上手時間  
將常用的 14 項功能以GUI(圖形介面)的形式供選用

> 功能介紹
- **顯示目標裝置資訊**: 目標裝置識別、識別CMS、伺服器服務類型、IP與網頁指紋
- **SSL/TLS 憑證檢查**: 檢查憑證簽發商、使用的加密方式...等
- **檔案列表**: 列出指定位置的所有資料 (可搭配 -l -a ...)
- **查看文件內容**: 列出指定檔案的內容以及兩個檔案的差異處 (可使用自適應檔案解碼)
- **IP狀態查詢**: 檢測與對方電腦的連線狀態、延遲，可使用 `範圍 IP` 以及 `查看特定 Port`
- **傳輸測試**: 可連接到其他設備並接收或發送訊息
- **埠口掃描**: 強大的掃描工具，可掃目標IP的所有Port口情況 (Open or Close)
- **路由追蹤**: 可檢測本機到對方IP中間經過了那些設備，以及中間每台設備的延遲
- **DNS查詢**: 查詢DNS、IP、Domain
- **網頁原始碼擷取**: HTTP(S)客戶端，可查詢HTML、HEADER ...等
- **弱密碼測試**: 強大的字典破解工具，可使用SSH、FTP、http(s)-get、http(S)-post-form
- **SSH連線**: 可使用IP位址搭配帳號密碼以command line方式遠端連線
- **列出網頁文件**: 將目標網頁的文件脈絡列出，方便知道目標網站的脈絡
- **掃描檔案/圖片隱藏資訊**: 顯示隱藏在檔案背後的資訊 (Ex: 照片位置、作者、有無隱寫檔案在內)

> 弱密碼測試 http-post-form
- **HTTP PATH**: 要破解的網站當前分頁 `Ex: 192.168.1.1/login.html` 就輸入 `/login.html`
- **User field**: 找尋當前網頁Source Code `User` 欄位的 `ID` 並填入
- **Pass field**: 找尋當前網頁Source Code `Password` 欄位的 `ID` 並填入
- **Failure string**: 填入當帳號密碼錯誤的時候會顯示的錯誤代碼 (請整行填入)