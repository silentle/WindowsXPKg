# Windows XP & Server 2003 Keygen

A key generation and validation tool based on reverse-engineering research, intended for educational and learning purposes.

## 📝 Introduction

This project is a tool for generating and validating product keys for Microsoft Windows XP and Windows Server 2003. You can use it not only to generate new, valid keys but also to check if your existing keys are legitimate.

All code is based on publicly available research, aiming to explore the application of digital signature algorithms in real-world scenarios.

## ⚙️ How It Works

The implementation of this project is primarily based on an in-depth study of the whitepaper **["Inside Windows Product Activation"](https://www.licenturion.com/xp/fully-licensed-wpa.txt)**.

The core principles are as follows:

1.  **Elliptic Curve Cryptography**: Windows' product activation mechanism uses the Elliptic Curve Digital Signature Algorithm (ECDSA) to verify the authenticity of product keys.
2.  **Private Key Signature**: A valid product key actually contains data (like a portion of the Product ID) signed with a Microsoft private key.
3.  **Reverse Engineering**: By analyzing the activation process, researchers successfully extracted the elliptic curve parameters and a valid **private key** used for signing.
4.  **Key Generation**: This program utilizes these public parameters and the leaked private key to simulate Microsoft's official signing process, thereby calculating new, mathematically legitimate product keys that can pass system validation.
5.  **Key Validation**: The program can also perform the reverse process, using Microsoft's **public key** to verify if the signature of a given product key is correct, thus determining its validity.

## 🚀 How to Use

1.  **Compile or Download**:
    *   You can directly use the pre-compiled executables in the `output/` directory: `keygen_xp.exe` (for Windows XP) or `Srv2003KG.exe` (for Windows Server 2003).
    *   Alternatively, you can compile it yourself by following the "How to Compile" section below.
2.  **Generate a Key**: Run the program, and it will automatically generate a 25-character product key.
3.  **Install the OS**: During the installation of Windows XP or Server 2003, enter the generated product key.
4.  **Activate by Phone**: After the installation is complete, you will be prompted to activate Windows. In the activation wizard, please select **"Activate by telephone"**.
5.  **Get Confirmation ID**: Open the [Microsoft Activation Page](https://msdev.gointeract.io/interact/index?interaction=1461173234028-3884f8602eccbe259104553afa8415434b4581-05d1&accountId=microsoft&appkey=196de13c-e946-4531-98f6-2719ec8405ce) and enter the **Installation ID** provided by the activation wizard into the webpage.
6.  **Complete Activation**: The webpage will return a **Confirmation ID**. Enter it back into the activation wizard to complete the activation.

## 🛠️ How to Compile

This project depends on the OpenSSL library. Please ensure you have it installed.

**Requirements:**

*   A C++ compiler (e.g., GCC/G++)
*   OpenSSL library (version > 0.9.8b)

**Compile Commands (using MinGW64/MSYS2):**

*   **To compile the Windows XP version:**
    ```bash
    g++ -Wall -Wextra -g3 main.cpp -o keygen_xp.exe -lssl -lcrypto
    ```

*   **To compile the Windows Server 2003 version:**
    ```bash
    g++ -Wall -Wextra -g3 Srv2003KGmain.cpp -o Srv2003KG.exe -lssl -lcrypto
    ```

## 🤖 AI-Assisted Note

Parts of this document (including structural optimization, detailed explanations, and language polishing) were generated with the assistance of an AI (GitHub Copilot) to provide a clearer and more comprehensive project overview.

## ⚠️ Disclaimer

This project is for technical research and educational purposes only. All code and documentation are based on public information. Do not use this project for any illegal or commercial activities. The developer assumes no responsibility for any consequences resulting from the use of this project.
