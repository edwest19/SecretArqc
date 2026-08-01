# 🔐 SecretArqc - Generate Application Cryptograms

## ⚖️ Legal

- **EMV®** is a registered trademark in the U.S. and other countries and an unregistered trademark elsewhere. The EMV trademark is owned by EMVCo, LLC.
- This is free software provided "AS IS" see LICENSE
- Not certified for production test bench only and use test keys

---

A comprehensive, spec-compliant implementation of EMV cryptographic operations including master key derivation, session key derivation, ARQC/ARPC generation for payment card processing.

[![.NET 10](https://img.shields.io/badge/.NET-10-blue.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/edwest19/SecretArqc/blob/main)
[![Release](https://img.shields.io/badge/release-v1.2.0-blue.svg)](https://github.com/edwest19/SecretArqc/releases/tag/v0.2.0)

---

## 🎯 Features

### ✅ Master Key Derivation

- **3DES Option A** - For PANs ≤ 16 digits
- **3DES Option B** - For PANs > 16 digits (with SHA-1 preprocessing)
- **AES** - AES-128/192/256 support
- **KCV Calculation** - Key Check Value for validation (3DES and AES)

### ✅ Session Key Derivation

- **3DES Session Keys** - Standard EMV 3DES derivation
- **AES Session Keys** - AES-CMAC based derivation
- **ATC-based** - Application Transaction Counter diversification

### ✅ ARQC Generation

- **ISO 9797-1 Algorithm 3** - Retail MAC (DES-CBC + 3DES final)
- **EMV 4.3 Compliant** - Matches specification examples
- **Validated** - Spec example A.3.3: `C20039270FE384D5` ✓

### ✅ ARPC Generation

- **Traditional Method 1** - 3DES with 2-byte ARC
- **CSU-based Method** - MAC4 with 4-byte Card Status Update
- **Validated** - Spec example A.3.4: `90EF477F` ✓

### ✅ User Interface

- **WinUI 3 Desktop App** - Modern Windows application
- **TLV Parser** - Paste complete transaction data, auto-extracts relevant tags
- **Config Management** - Save/load configurations for different test scenarios
- **Hex Input Formatting** - Auto-clean spaces, line breaks, tabs, hyphens
- **Multiline Input** - Paste formatted EMV spec data directly
- **Real-time Validation** - KCV display, length checking
- **Intermediate Steps Log** - Debug and verify calculations

### ✅ CLI Tools

- `SecretArqc.MasterKey` - Master key derivation
- `SecretArqc.SKD` - Session key derivation  
- `SecretArqc.Arqc` - ARQC computation
- Scriptable and automatable

---

## 📋 EMV Specification Compliance

This implementation has been validated against **EMV 4.3 Book 2** test vectors:

| Spec Section | Description | Expected | Actual | Status |
| ------------ | ----------- | -------- | ------ | ------ |
| **A.3.1** | Master Key Derivation (Option A) | `08DF3425322020A7...` | `08DF3425322020A7...` | ✅ |
| **A.3.1.1** | Long PAN (Option B, SHA-1) | See Note¹ | `201FDA159D1A54F8...` | ✅ |
| **A.3.2** | Session Key Derivation | `182025BA4FAB32F5...` | `182025BA4FAB32F5...` | ✅ |
| **A.3.3** | ARQC Generation | `C20039270FE384D5` | `C20039270FE384D5` | ✅ |
| **A.3.4** | ARPC Generation (CSU) | `90EF477F` | `90EF477F` | ✅ |

**Note¹:** EMV spec A.3.1.1 contains a typographical error in the intermediate XOR calculation. Our implementation produces the mathematically correct result, validated for consistency across all tools.

---

## 🚀 Quick Start

### Requirements

- Windows 10 (version 10.0.17763.0 or later) / Windows 11
- .NET 10 SDK
- Visual Studio 2022 (for building from source)

### Installation

**Option 1: Build from Source**
git clone [SecretArqc.git](https://github.com/edwest19/SecretArqc.git)

cd SecretArqc

dotnet build ./SecretArqc.slnx --configuration Release

**Option 2: Run Pre-built Releases**
Download from [Releases](https://github.com/edwest19/SecretArqc/releases) page

SecretArqc.GenAc.msix - install winui3 app

These .exe files can be downloaded to a folder and run

SecretArqc.MasterKey.exe - Calculate card master key from MKac, PAN and PSN

SecretArqc.SKD.exe - session key derivation

SecretArqc.Arqc.exe - Calculate ARQC

### Usage Examples

Run the .exe files like this for powershell after cd to the directory containing the .exe files

.\SecretArqc.MasterKey.exe A 9E15204313F7318ACB79B90BD986AD29 5413330089010000 01

.\SecretArqc.SKD.exe 08DF3425322020A720EFF2C1343852E63D 3456

.\SecretArqc.Arqc.exe 182025BA4FAB32F5A63A1BA5E6845D4E 000000010000000000001000084000000000840980704001111111158003456

#### Desktop Application

dotnet run --project SecretArqc.GenAC

**Example Workflow:**

1. Enter IMK-AC: `9E 15 20 43 13 F7 31 8A CB 79 B9 0B D9 86 AD 29`
2. Tab away → auto-cleans to `9E15204313F7318ACB79B90BD986AD29`
3. Enter PAN, PSN, ATC
4. Generate keys with one click

## CLI Examples (continued)

### ARQC Generation

dotnet run --project SecretArqc.Arqc -- 182025BA4FAB32F5A63A1BA5E6845D4E 0000000100000000000010000840000000108008409807040011111111580034560FA500A03800000000000000000000000F010000000000000000000000000000

### Master Key Derivation  

dotnet run --project SecretArqc.MasterKey -- 9E15204313F7318ACB79B90BD986AD29 541333900000006165 00

### Session Key Derivation

dotnet run --project SecretArqc.SKD -- 08DF3425322020A720EFF2C1343852E63D 3456

## Architecture (continued)

SecretArqc/
├── SecretArqc.Core/              # Core cryptographic engines
├── SecretArqc.GenAC/             # WinUI 3 Desktop App
├── SecretArqc.MasterKey/         # CLI: Master Key
├── SecretArqc.SKD/               # CLI: Session Key
├── SecretArqc.Arqc/              # CLI: ARQC
└── SecretArqc.Core.Tests/        # Unit tests

---

## 🧪 Testing

dotnet test SecretArqc.Core.Tests

---

## 📖 Documentation

- [EMVCo Enabling Seamless and Secure Payments Worldwide](https://www.emvco.com/)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests
4. Submit a pull request

---

## 📄 License

MIT License - See LICENSE file.

---

## ⚡ Built with .NET 10 | 🔐 EMV 4.3 Compliant | 🚀 v1.1.0
