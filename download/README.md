# Download Securidge Vault

## ⬇️ [Download for Windows (64-bit)](https://github.com/securidge/securidge-vault/releases/latest/download/SecuridgeVault-windows-x64.zip)

This link always gives you the **newest release**. Older versions and release
notes: [all releases](https://github.com/securidge/securidge-vault/releases).

> ⚠️ **Pre-alpha, not independently audited.** Do not use it for data you
> cannot afford to lose, and keep other copies of your files.

### How to run

1. Download `SecuridgeVault-windows-x64.zip` and unzip it anywhere (a USB drive works too).
2. Double-click **`SecuridgeVault.exe`**. There is no installer and it needs no admin rights.
3. Windows may show **"Windows protected your PC"** because the program is not
   code-signed yet. Click **More info → Run anyway** only after checking the download (below).
4. Start with **Create a key file**. To switch to Korean, use **Language / 언어** at the top right.

What is in the zip:

| File | What |
|---|---|
| `SecuridgeVault.exe` | The desktop app |
| `securidge-vault.exe` | Command-line version, for scripts |
| `README.md`, `LICENSE-*`, `SECURITY.md` | Documentation and licences |

### Check the download

Each release lists SHA-256 checksums (`SHA256SUMS.txt`). In PowerShell:

```powershell
Get-FileHash .\SecuridgeVault-windows-x64.zip
```

The result must match the line for `SecuridgeVault-windows-x64.zip` in
`SHA256SUMS.txt` on the release page. With the [GitHub CLI](https://cli.github.com/)
you can also confirm the file was built by this repository's workflow:

```text
gh attestation verify SecuridgeVault-windows-x64.zip -R securidge/securidge-vault
```

> Why is there no `.exe` in this folder? Programs are published as
> [GitHub Releases](https://github.com/securidge/securidge-vault/releases), not
> committed to the source code: each release is built and checksummed
> automatically from the tagged source, and the link above never goes stale.

---

## 한국어 안내

## ⬇️ [Windows용 다운로드 (64비트)](https://github.com/securidge/securidge-vault/releases/latest/download/SecuridgeVault-windows-x64.zip)

위 링크는 항상 **최신 버전**을 내려받습니다. 이전 버전과 변경 내용은
[전체 릴리스](https://github.com/securidge/securidge-vault/releases)에서 볼 수 있습니다.

> ⚠️ **시험판(프리알파)이며 외부 보안 감사를 받지 않았습니다.** 잃으면 안 되는
> 데이터에는 쓰지 마시고, 원본 파일은 다른 곳에도 사본을 두세요.

### 실행 방법

1. `SecuridgeVault-windows-x64.zip`을 내려받아 원하는 곳에 압축을 풉니다 (USB 드라이브도 됩니다).
2. **`SecuridgeVault.exe`** 를 더블클릭합니다. 설치 과정이 없고 관리자 권한도 필요 없습니다.
3. 아직 코드 서명이 되어 있지 않아 **"Windows의 PC 보호"** 창이 뜰 수 있습니다.
   아래 방법으로 파일을 확인한 뒤 **추가 정보 → 실행** 을 누르세요.
4. 오른쪽 위 **Language / 언어** 메뉴에서 **한국어** 를 고르면 모든 메뉴가 한국어로 바뀝니다.
   선택한 언어는 프로그램 옆 `settings.toml`에 기억됩니다.
5. 처음이라면 **키 파일 만들기** 부터 시작하세요. 백업 2개 만들기까지 화면이 안내합니다.

### 내려받은 파일 확인하기

PowerShell에서 아래 명령을 실행해, 결과가 릴리스 페이지의 `SHA256SUMS.txt`에 있는
`SecuridgeVault-windows-x64.zip` 값과 같은지 확인하세요.

```powershell
Get-FileHash .\SecuridgeVault-windows-x64.zip
```
