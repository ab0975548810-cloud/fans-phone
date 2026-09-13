# fans-phone POS

手機玻璃貼、手機殼與配件使用的單店獨立 POS。

## 目前版本

V1.5.2

## 程式與資料分離

- GitHub：只放程式碼與前端檔案。
- Zeabur `/data/pos.db`：保存正式營業資料。
- Zeabur `/data/POS_Backup/`：保存自動與手動備份。
- 更新程式時不可刪除 `/data` Volume，也不可用新的空白 `pos.db` 覆蓋正式資料。

## 更新流程

1. POS 設定頁先按「立即備份」。
2. 將新版程式提交到 `main`。
3. Zeabur 重新部署新版程式。
4. 新版程式繼續讀取原本 `/data/pos.db`。
5. 上線後確認店名、人員、庫存、歷史訂單及報表資料皆正常。

## 備份

系統啟動時會建立一份備份，之後每小時自動備份。另保留每日備份，並可由設定頁手動建立與下載備份。

## 重要檔案

- `app.py`：Flask 後端
- `templates/index.html`：POS 前端
- `static/image.png`：手寫報表貓咪浮水印
- `requirements.txt`：Python 套件

## 不可提交到 GitHub

`.gitignore` 已排除：

- `pos.db`
- `*.db`
- `POS_Backup/`
- `.pos_secret_key`
- `.env`
- Python 快取檔

## 檢查更新

V1.5.2 起，POS 設定頁可按「檢查更新」比對 `version.json`。此功能只檢查版本，不會在 POS 內直接安裝；正式更新仍由 GitHub `main` → Zeabur 部署。
