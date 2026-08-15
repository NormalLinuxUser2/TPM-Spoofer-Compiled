# TPM-Spoofer

(updated // 8/15/2026)
<br>
A Windows tool for spoofing the TPM 2.0 Endorsement Key (EK) by modifying persistent handles.  
Built using the `go-tpm` library.

---


## ⚠️ REQUIRED: TPM CLEAR (BEFORE SPOOFING)

You **MUST clear the TPM before using this tool**.

### Spoof steps

1. Open **PowerShell**
2. Type **Clear-TPM**
3. Run as admin tpm-spoofer.exe
4. Reboot your PC and check your TPM serials

USAGE: https://www.youtube.com/watch?v=AUCJlpRXFKA

---

## Installation & Build

```cmd
go mod init tpm-spoof

go get github.com/google/go-tpm/tpm2

go mod tidy

go build -o tpm-spoof.exe
