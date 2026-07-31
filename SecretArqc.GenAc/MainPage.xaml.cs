using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using SecretArqc.Core.Emv;
using SecretArqc.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace SecretArqc_GenAc;

/// <summary>
/// The main content page displayed inside the application window.
/// Ported from SecretEmv.GenAC's AcGenPage, retargeted to SecretArqc.Core
/// and updated to use FontIcon glyphs (Segoe Fluent Icons) instead of
/// emoji for status indicators and section iconography.
/// </summary>
[SupportedOSPlatform("windows10.0.17763.0")]
public sealed partial class MainPage : Page
{
    private static readonly HashSet<string> AllowedDolTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "9F02",  // Amount, Authorised (Numeric)
        "9F03",  // Amount, Other (Numeric)
        "9F1A",  // Terminal Country Code
        "95",    // Terminal Verification Results
        "5F2A",  // Transaction Currency Code
        "9A",    // Transaction Date
        "9C",    // Transaction Type
        "9F37",  // Unpredictable Number
        "82",    // Application Interchange Profile
        "9F36",  // Application Transaction Counter (ATC)
        "9F10"   // Issuer Application Data (IAD)
    };

    // Segoe Fluent Icons glyphs used for ARQC/ARPC status indicators.
    private const string GlyphCheckMark = "\uE73E"; // CheckMark
    private const string GlyphError = "\uE783";      // Error

    private readonly EmvCryptoPipelineService _pipeline = new();
    private const string AutoSaveFileName = "autosave_config.json";
    private bool _isLoadingConfig = false;

    public MainPage()
    {
        InitializeComponent();
        AutoLoadConfiguration();

        // Set default values
        Rb3Des.IsChecked = true;
        Rb3DesOptionA.IsChecked = true;
        RbAes128.IsChecked = true;
    }

    /// <summary>
    /// Cleans hex input by removing spaces, line breaks, tabs, and hyphens.
    /// Allows users to paste formatted hex like "00 00 00" or multi-line hex.
    /// </summary>
    private static string CleanHexInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return new string(input
            .Where(c => char.IsLetterOrDigit(c))  // Only keep letters and digits
            .ToArray())
            .ToUpperInvariant();
    }

    /// <summary>
    /// Validates that a string contains only valid hex characters.
    /// </summary>
    private static bool IsValidHex(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        return input.All(c => (c >= '0' && c <= '9') ||
                              (c >= 'A' && c <= 'F') ||
                              (c >= 'a' && c <= 'f'));
    }

    /// <summary>
    /// Shows a success (CheckMark) or failure (Error) glyph on a status FontIcon.
    /// </summary>
    private static void SetStatusIcon(FontIcon icon, bool success)
    {
        icon.Glyph = success ? GlyphCheckMark : GlyphError;
        icon.Foreground = new SolidColorBrush(success
            ? Color.FromArgb(255, 16, 124, 16)   // green
            : Color.FromArgb(255, 196, 43, 28));  // red
        icon.Visibility = Visibility.Visible;
    }

    private static void ClearStatusIcon(FontIcon icon)
    {
        icon.Visibility = Visibility.Collapsed;
    }

    private void BlockCipher_Checked(object sender, RoutedEventArgs e)
    {
        if (Rb3Des == null || RbAes == null)
            return;

        bool is3Des = Rb3Des.IsChecked == true;

        Rb3DesOptionA.IsEnabled = is3Des;
        Rb3DesOptionB.IsEnabled = is3Des;
        RbAesOption3.IsEnabled = !is3Des;

        if (AesKeyLengthPanel != null)
            AesKeyLengthPanel.Visibility = is3Des ? Visibility.Collapsed : Visibility.Visible;

        if (is3Des)
        {
            Rb3DesOptionA.IsChecked = true;
        }
        else
        {
            RbAesOption3.IsChecked = true;
        }
    }

    private void AesKeyLength_Checked(object sender, RoutedEventArgs e)
    {
        // AES key length selection handled by radio buttons
    }

    private void ImkAc_TextChanged(object sender, TextChangedEventArgs e)
    {
        CalculateAndDisplayKcv();
        AutoSaveConfiguration();
    }

    private void Pan_TextChanged(object sender, TextChangedEventArgs e)
    {
        // Clean the PAN text (remove spaces during typing)
        string cleanPan = CleanHexInput(TxtPan.Text);
        int len = cleanPan.Length;

        if (Rb3Des.IsChecked == true)
        {
            Rb3DesOptionA.IsEnabled = true;
            Rb3DesOptionB.IsEnabled = true;

            if (len <= 16)
            {
                Rb3DesOptionA.IsChecked = true;
                Rb3DesOptionB.IsChecked = false;
            }
            else
            {
                Rb3DesOptionA.IsChecked = false;
                Rb3DesOptionB.IsChecked = true;
            }
        }

        AutoSaveConfiguration();
    }

    /// <summary>
    /// Calculates and displays the KCV (Key Check Value) for the entered IMK-AC
    /// </summary>
    private void CalculateAndDisplayKcv()
    {
        try
        {
            string imkHex = CleanHexInput(TxtImkAc.Text);

            if (string.IsNullOrWhiteSpace(imkHex))
            {
                TxtImkKcv.Text = string.Empty;
                return;
            }

            byte[] imk = Convert.FromHexString(imkHex);
            string kcv;

            if (Rb3Des.IsChecked == true)
            {
                // 3DES KCV: Encrypt 8 zero bytes with 3DES, take first 3 bytes
                if (imk.Length != 16 && imk.Length != 24)
                {
                    TxtImkKcv.Text = "KCV: (IMK must be 16 or 24 bytes for 3DES)";
                    return;
                }

                var tdes = new SecretArqc.Core.Crypto.TripleDesEngine();
                byte[] zeros = new byte[8];
                byte[] encrypted = tdes.EncryptBlock(imk, zeros);
                kcv = Convert.ToHexString(encrypted).Substring(0, 6);
            }
            else
            {
                // AES KCV: Encrypt 16 zero bytes with AES, take first 3 bytes
                if (imk.Length != 16 && imk.Length != 24 && imk.Length != 32)
                {
                    TxtImkKcv.Text = "KCV: (IMK must be 16, 24, or 32 bytes for AES)";
                    return;
                }

                var aes = new SecretArqc.Core.Crypto.AesEngine();
                byte[] zeros = new byte[16];
                byte[] encrypted = aes.EncryptBlock(imk, zeros);
                kcv = Convert.ToHexString(encrypted).Substring(0, 6);
            }

            TxtImkKcv.Text = $"KCV: {kcv}";
        }
        catch (Exception)
        {
            TxtImkKcv.Text = "KCV: (invalid hex)";
        }
    }

    private void GenerateCardMasterKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string imkHex = CleanHexInput(TxtImkAc.Text);
            string pan = CleanHexInput(TxtPan.Text);
            string psn = CleanHexInput(TxtPsn.Text);

            if (string.IsNullOrWhiteSpace(imkHex) || string.IsNullOrWhiteSpace(pan) || string.IsNullOrWhiteSpace(psn))
            {
                AppendLog("ERROR: IMK-AC, PAN, and PSN are required.");
                return;
            }

            byte[] imk = Convert.FromHexString(imkHex);
            byte[] cmk;

            if (Rb3Des.IsChecked == true)
            {
                if (Rb3DesOptionA.IsChecked == true)
                {
                    cmk = _pipeline.DeriveDesIccMasterKeyOptionA(imk, pan, psn);
                    AppendLog("Card Master Key generated (3DES Option A).");
                }
                else
                {
                    cmk = _pipeline.DeriveDesIccMasterKeyOptionB(imk, pan, psn);
                    AppendLog("Card Master Key generated (3DES Option B).");
                }
            }
            else
            {
                cmk = _pipeline.DeriveAesIccMasterKey(imk, pan, psn);
                AppendLog("Card Master Key generated (AES).");
            }

            TxtCardMasterKey.Text = Convert.ToHexString(cmk);
        }
        catch (Exception ex)
        {
            AppendLog($"ERROR: {ex.Message}");
        }
    }

    private void GenerateSessionKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string cmkHex = CleanHexInput(TxtCardMasterKey.Text);
            string atcHex = CleanHexInput(TxtAtc.Text);

            if (string.IsNullOrWhiteSpace(cmkHex) || string.IsNullOrWhiteSpace(atcHex))
            {
                AppendLog("ERROR: Card Master Key and ATC are required.");
                return;
            }

            byte[] cmk = Convert.FromHexString(cmkHex);
            byte[] sessionKey;

            if (Rb3Des.IsChecked == true)
            {
                sessionKey = _pipeline.DeriveDesSessionKey(cmk, atcHex);
                AppendLog("Session Key generated (3DES).");
            }
            else
            {
                sessionKey = _pipeline.DeriveAesSessionKey(cmk, atcHex);
                AppendLog("Session Key generated (AES).");
            }

            TxtSessionKey.Text = Convert.ToHexString(sessionKey);
        }
        catch (Exception ex)
        {
            AppendLog($"ERROR: {ex.Message}");
        }
    }

    private void GenerateArqc_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string sessionKeyHex = CleanHexInput(TxtSessionKey.Text);
            string tagValuesHex = CleanHexInput(TxtTagValues.Text);

            if (string.IsNullOrWhiteSpace(sessionKeyHex) || string.IsNullOrWhiteSpace(tagValuesHex))
            {
                AppendLog("ERROR: Session Key and Tag Values are required.");
                return;
            }

            byte[] dolBytes = Array.Empty<byte>();
            byte[] tagValuesBytes = Convert.FromHexString(tagValuesHex);

            var result = _pipeline.GenerateArqc(sessionKeyHex, dolBytes, tagValuesBytes);

            // Display ARQC
            TxtArqc.Text = result.Arqc;
            SetStatusIcon(TxtArqcStatus, success: true);
            AppendLog("ARQC generated.");
            AutoSaveConfiguration();
        }
        catch (Exception ex)
        {
            SetStatusIcon(TxtArqcStatus, success: false);
            AppendLog($"ERROR (ARQC): {ex.Message}");
            AppendLog($"Stack: {ex.StackTrace}");
        }
    }

    private void GenerateArpc_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string arqcHex = CleanHexInput(TxtArqc.Text);
            string arcHex = CleanHexInput(TxtArc.Text);
            string sessionKeyHex = CleanHexInput(TxtSessionKey.Text);

            if (string.IsNullOrWhiteSpace(arqcHex) || string.IsNullOrWhiteSpace(arcHex) || string.IsNullOrWhiteSpace(sessionKeyHex))
            {
                AppendLog("ERROR: ARQC, ARC/CSU, and Session Key are required.");
                return;
            }

            var input = new ArpcInput
            {
                Arqc = arqcHex,
                Arc = arcHex,
                SessionKeyAc = sessionKeyHex
            };

            var result = _pipeline.GenerateArpc(input);

            // Display ARPC
            TxtArpc.Text = result.Arpc;
            SetStatusIcon(TxtArpcStatus, success: true);
            AppendLog("ARPC generated.");
            AutoSaveConfiguration();
        }
        catch (Exception ex)
        {
            SetStatusIcon(TxtArpcStatus, success: false);
            AppendLog($"ERROR (ARPC): {ex.Message}");
        }
    }

    /// <summary>
    /// Handles DOL text changes - parses TLV format if detected and extracts only allowed tags
    /// </summary>
    private void TxtDol_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isLoadingConfig) return;

        try
        {
            string input = TxtDol.Text.Trim();
            if (string.IsNullOrWhiteSpace(input))
                return;

            // Clean the input first (remove spaces/line breaks)
            string cleanedInput = CleanHexInput(input);

            // Only process if it's valid hex
            if (!IsValidHex(cleanedInput))
                return;

            byte[] data = Convert.FromHexString(cleanedInput);

            // Try to parse as TLV and extract values for allowed tags only
            string extractedValues = ParseTlvWithFilter(data);

            if (!string.IsNullOrEmpty(extractedValues))
            {
                // Auto-populate tag values with only the allowed tags
                TxtTagValues.Text = extractedValues;
                AppendLog($"TLV data detected - extracted values for standard DOL tags.");
            }
        }
        catch
        {
            // Silently fail - user might still be typing or it's just a DOL (tags only)
        }
    }

    private void AppendLog(string message)
    {
        string timestamp = DateTime.Now.ToString("HH:mm:ss");
        TxtLog.Text += $"{timestamp} {message}\n";

        // Auto-scroll to bottom
        if (TxtLog.Parent is ScrollViewer scrollViewer)
        {
            scrollViewer.ChangeView(null, scrollViewer.ScrollableHeight, null);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        // Close the application
        Application.Current.Exit();
    }

    // -----------------------------
    // Configuration Management
    // -----------------------------

    /// <summary>
    /// Auto-saves current configuration to AppData
    /// </summary>
    private async void AutoSaveConfiguration()
    {
        if (_isLoadingConfig) return; // Don't auto-save while loading

        try
        {
            var config = CaptureCurrentConfiguration();
            config.ConfigName = "AutoSave";

            var localFolder = ApplicationData.Current.LocalFolder;
            var file = await localFolder.CreateFileAsync(AutoSaveFileName, CreationCollisionOption.ReplaceExisting);

            string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            await FileIO.WriteTextAsync(file, json);
        }
        catch
        {
            // Silently fail auto-save
        }
    }

    /// <summary>
    /// Auto-loads configuration from AppData on startup
    /// </summary>
    private async void AutoLoadConfiguration()
    {
        try
        {
            var localFolder = ApplicationData.Current.LocalFolder;
            var file = await localFolder.TryGetItemAsync(AutoSaveFileName) as StorageFile;

            if (file != null)
            {
                string json = await FileIO.ReadTextAsync(file);
                var config = JsonSerializer.Deserialize<EmvConfiguration>(json);

                if (config != null)
                {
                    ApplyConfiguration(config);
                    if (TxtConfigStatus != null)
                        TxtConfigStatus.Text = $"Restored from last session ({config.SavedAt:g})";
                }
            }
        }
        catch
        {
            // Silently fail if no auto-save exists
        }
    }

    /// <summary>
    /// Manual save with file picker
    /// </summary>
    private async void SaveConfig_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var savePicker = new FileSavePicker();

            // Get window handle
            var window = App.CurrentWindow;
            if (window == null) return;

            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            WinRT.Interop.InitializeWithWindow.Initialize(savePicker, hwnd);

            savePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            savePicker.FileTypeChoices.Add("EMV Configuration", new List<string> { ".json" });
            savePicker.SuggestedFileName = $"emv_config_{DateTime.Now:yyyyMMdd_HHmmss}";

            StorageFile file = await savePicker.PickSaveFileAsync();

            if (file != null)
            {
                var config = CaptureCurrentConfiguration();
                config.ConfigName = System.IO.Path.GetFileNameWithoutExtension(file.Name);

                string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                await FileIO.WriteTextAsync(file, json);

                if (TxtConfigStatus != null)
                    TxtConfigStatus.Text = $"Saved: {file.Name}";
                AppendLog($"Configuration saved to {file.Name}");
            }
        }
        catch (Exception ex)
        {
            if (TxtConfigStatus != null)
                TxtConfigStatus.Text = "Save failed";
            AppendLog($"ERROR saving configuration: {ex.Message}");
        }
    }

    /// <summary>
    /// Manual load with file picker
    /// </summary>
    private async void LoadConfig_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var openPicker = new FileOpenPicker();

            // Get window handle
            var window = App.CurrentWindow;
            if (window == null) return;

            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            WinRT.Interop.InitializeWithWindow.Initialize(openPicker, hwnd);

            openPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            openPicker.FileTypeFilter.Add(".json");

            StorageFile file = await openPicker.PickSingleFileAsync();

            if (file != null)
            {
                string json = await FileIO.ReadTextAsync(file);
                var config = JsonSerializer.Deserialize<EmvConfiguration>(json);

                if (config != null)
                {
                    ApplyConfiguration(config);
                    if (TxtConfigStatus != null)
                        TxtConfigStatus.Text = $"Loaded: {file.Name}";
                    AppendLog($"Configuration loaded from {file.Name}");
                }
            }
        }
        catch (Exception ex)
        {
            if (TxtConfigStatus != null)
                TxtConfigStatus.Text = "Load failed";
            AppendLog($"ERROR loading configuration: {ex.Message}");
        }
    }

    /// <summary>
    /// Clear all fields
    /// </summary>
    private void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        _isLoadingConfig = true;

        // Clear all text fields
        TxtImkAc.Text = string.Empty;
        TxtPan.Text = string.Empty;
        TxtPsn.Text = string.Empty;
        TxtCardMasterKey.Text = string.Empty;
        TxtAtc.Text = string.Empty;
        TxtSessionKey.Text = string.Empty;
        TxtDol.Text = string.Empty;
        TxtTagValues.Text = string.Empty;
        TxtArc.Text = string.Empty;
        TxtArqc.Text = string.Empty;
        TxtArpc.Text = string.Empty;
        TxtLog.Text = string.Empty;
        TxtImkKcv.Text = string.Empty;

        // Reset status indicators
        if (TxtArqcStatus != null)
            ClearStatusIcon(TxtArqcStatus);
        if (TxtArpcStatus != null)
            ClearStatusIcon(TxtArpcStatus);

        // Reset to defaults
        Rb3Des.IsChecked = true;
        Rb3DesOptionA.IsChecked = false;
        Rb3DesOptionB.IsChecked = false;

        if (TxtConfigStatus != null)
            TxtConfigStatus.Text = "Ready";
        AppendLog("All fields cleared");

        _isLoadingConfig = false;
    }

    /// <summary>
    /// Captures current UI state into a configuration object
    /// </summary>
    private EmvConfiguration CaptureCurrentConfiguration()
    {
        return new EmvConfiguration
        {
            SavedAt = DateTime.Now,
            Use3Des = Rb3Des.IsChecked == true,
            DerivationMethod = Rb3DesOptionA.IsChecked == true ? "OptionA" :
                              Rb3DesOptionB.IsChecked == true ? "OptionB" : "Option3",
            AesKeyLength = RbAes128?.IsChecked == true ? 128 :
                          RbAes192?.IsChecked == true ? 192 : 256,
            ImkAc = TxtImkAc.Text.Trim(),
            Pan = TxtPan.Text.Trim(),
            Psn = TxtPsn.Text.Trim(),
            CardMasterKey = TxtCardMasterKey.Text.Trim(),
            Atc = TxtAtc.Text.Trim(),
            SessionKey = TxtSessionKey.Text.Trim(),
            Dol = TxtDol.Text.Trim(),
            TagValues = TxtTagValues.Text.Trim(),
            Arc = TxtArc.Text.Trim(),
            Arqc = TxtArqc.Text.Trim(),
            Arpc = TxtArpc.Text.Trim()
        };
    }

    /// <summary>
    /// Applies a configuration object to the UI
    /// </summary>
    private void ApplyConfiguration(EmvConfiguration config)
    {
        _isLoadingConfig = true;

        // Cipher settings
        Rb3Des.IsChecked = config.Use3Des;
        RbAes.IsChecked = !config.Use3Des;

        switch (config.DerivationMethod)
        {
            case "OptionA":
                Rb3DesOptionA.IsChecked = true;
                break;
            case "OptionB":
                Rb3DesOptionB.IsChecked = true;
                break;
            case "Option3":
                RbAesOption3.IsChecked = true;
                break;
        }

        if (config.AesKeyLength == 128)
            RbAes128.IsChecked = true;
        else if (config.AesKeyLength == 192)
            RbAes192.IsChecked = true;
        else
            RbAes256.IsChecked = true;

        // Fields
        TxtImkAc.Text = config.ImkAc;
        TxtPan.Text = config.Pan;
        TxtPsn.Text = config.Psn;
        TxtCardMasterKey.Text = config.CardMasterKey;
        TxtAtc.Text = config.Atc;
        TxtSessionKey.Text = config.SessionKey;
        TxtDol.Text = config.Dol;
        TxtTagValues.Text = config.TagValues;

        // Skip ARC if it's the old default value "3030"
        // This handles migration from old configs
        if (!string.IsNullOrEmpty(config.Arc) && config.Arc != "3030")
        {
            TxtArc.Text = config.Arc;
        }
        else
        {
            TxtArc.Text = string.Empty;
        }

        TxtArqc.Text = config.Arqc;
        TxtArpc.Text = config.Arpc;

        // Update status
        if (TxtArqcStatus != null && !string.IsNullOrEmpty(config.Arqc))
            SetStatusIcon(TxtArqcStatus, success: true);
        if (TxtArpcStatus != null && !string.IsNullOrEmpty(config.Arpc))
            SetStatusIcon(TxtArpcStatus, success: true);

        _isLoadingConfig = false;
    }

    /// <summary>
    /// Handles LostFocus event for hex input textboxes.
    /// Automatically cleans and formats hex input (removes spaces, hyphens, line breaks, etc.)
    /// </summary>
    private void HexTextBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is TextBox textBox && !_isLoadingConfig)
        {
            string originalText = textBox.Text;
            string cleanedText = CleanHexInput(originalText);

            // Only update if text changed
            if (originalText != cleanedText)
            {
                // Temporarily disable TextChanged events to avoid recursion
                int cursorPos = textBox.SelectionStart;
                textBox.Text = cleanedText;

                // Try to restore cursor position
                try
                {
                    if (cursorPos <= cleanedText.Length)
                        textBox.SelectionStart = Math.Min(cursorPos, cleanedText.Length);
                }
                catch
                {
                    // Ignore cursor position errors
                }
            }
        }
    }

    /// <summary>
    /// Parses TLV data and extracts values only for tags in the allowed DOL list.
    /// Returns concatenated hex string of values in the order they appear in the TLV.
    /// </summary>
    private string ParseTlvWithFilter(byte[] data)
    {
        var valueList = new List<byte>();
        int offset = 0;

        while (offset < data.Length)
        {
            // Parse tag
            byte firstByte = data[offset++];

            var tagBytes = new List<byte> { firstByte };

            // Check if multi-byte tag
            if ((firstByte & 0x1F) == 0x1F)
            {
                while (offset < data.Length && (data[offset] & 0x80) != 0)
                {
                    tagBytes.Add(data[offset++]);
                }
                if (offset < data.Length)
                    tagBytes.Add(data[offset++]);
            }

            string tag = Convert.ToHexString(tagBytes.ToArray());

            if (offset >= data.Length)
                break;

            // Parse length
            int length = data[offset++];

            // Check if we have value bytes
            if (offset + length <= data.Length)
            {
                // Only extract if tag is in our allowed list
                if (AllowedDolTags.Contains(tag))
                {
                    for (int i = 0; i < length; i++)
                    {
                        valueList.Add(data[offset++]);
                    }
                }
                else
                {
                    // Skip this tag's value (not in allowed list)
                    offset += length;
                }
            }
            else
            {
                // Not enough bytes for value, this is DOL-only format (no values)
                return string.Empty;
            }
        }

        return valueList.Count > 0 ? Convert.ToHexString(valueList.ToArray()) : string.Empty;
    }
}
