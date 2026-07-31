using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using WinRT.Interop;

namespace TVTimeRecovery.Windows;

public sealed partial class MainWindow : Window
{
    private string? _backupPath;
    private string _sourceKind = "android_legacy_backup";
    private CancellationTokenSource? _cancellation;
    private ValidatedRecoveryOutput? _completedOutput;

    public MainWindow()
    {
        InitializeComponent();
        SourceKind.SelectedIndex = 0;
        Closed += (_, _) => _completedOutput?.Dispose();
    }

    private async void SelectBackup_Click(object sender, RoutedEventArgs e)
    {
        IStorageItem? selectedItem;
        if (_sourceKind == "android_preserved_snapshot")
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            selectedItem = await picker.PickSingleFolderAsync();
        }
        else
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            selectedItem = await picker.PickSingleFileAsync();
        }
        if (selectedItem is null) return;
        _backupPath = selectedItem.Path;
        SelectionStatus.Text = "Private local source selected";
        RecoverButton.IsEnabled = true;
        StatusBar.Title = "Source selected";
        StatusBar.Message = "The app will validate the selected source before accepting any completed report.";
    }

    private void SourceKind_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (SourceKind.SelectedItem is not ComboBoxItem item || item.Tag is not string kind) return;
        _sourceKind = kind;
        _backupPath = null;
        _completedOutput?.Dispose();
        _completedOutput = null;
        ResultActions.Visibility = Visibility.Collapsed;
        SelectionStatus.Text = "No source selected";
        RecoverButton.IsEnabled = false;
        SelectBackupButton.Content = kind switch
        {
            "android_preserved_snapshot" => "Select preserved Android database folder",
            "android_legacy_backup" => "Select Android backup file",
            _ => "Select official TV Time export",
        };
        BackupPassword.Header = "Export password (only if the ZIP is encrypted)";
        BackupPassword.IsEnabled = kind == "tvtime_official_export";
        BackupPassword.Password = string.Empty;
    }

    private async void Recover_Click(object sender, RoutedEventArgs e)
    {
        if (_backupPath is null || SensitiveConfirmation.IsChecked != true)
        {
            StatusBar.Severity = InfoBarSeverity.Warning;
            StatusBar.Title = "Confirmation required";
            StatusBar.Message = "Complete the required source password and sensitive-output confirmation.";
            return;
        }

        RecoverButton.IsEnabled = false;
        SelectBackupButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        _completedOutput?.Dispose();
        _completedOutput = null;
        ResultActions.Visibility = Visibility.Collapsed;
        _cancellation = new CancellationTokenSource();
        try
        {
            var outputParent = PrivateRecoveryStore.RequireEncryptedParent();
            var output = PrivateRecoveryStore.FreshOutput(outputParent);
            var password = BackupPassword.Password;
            BackupPassword.Password = string.Empty;
            var recovery = new RecoveryCoordinator();
            _completedOutput = await recovery.RecoverAsync(
                _sourceKind,
                _backupPath,
                output,
                password,
                progress => DispatcherQueue.TryEnqueue(() =>
                {
                    StatusBar.Severity = InfoBarSeverity.Informational;
                    StatusBar.Title = "Recovery in progress";
                    StatusBar.Message = progress;
                }),
                _cancellation.Token);
            ResultActions.Visibility = Visibility.Visible;
            StatusBar.Severity = InfoBarSeverity.Success;
            StatusBar.Title = "Recovery complete";
            StatusBar.Message = "The private Markdown and offline HTML reports are ready in app-managed storage.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryCompleted);
        }
        catch (OperationCanceledException)
        {
            StatusBar.Severity = InfoBarSeverity.Warning;
            StatusBar.Title = "Recovery cancelled";
            StatusBar.Message = "Incomplete output was preserved. Start again with a fresh private folder.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryCancelled);
        }
        catch (RecoveryUserException error)
        {
            StatusBar.Severity = InfoBarSeverity.Error;
            StatusBar.Title = "Recovery stopped safely";
            StatusBar.Message = error.SafeMessage;
            RecoveryDiagnostics.Record(error.Diagnostic);
        }
        catch
        {
            StatusBar.Severity = InfoBarSeverity.Error;
            StatusBar.Title = "Recovery stopped safely";
            StatusBar.Message = "No completed report was accepted. The source backup was not intentionally modified.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.UnrecognizedFailure);
        }
        finally
        {
            _cancellation?.Dispose();
            _cancellation = null;
            CancelButton.IsEnabled = false;
            SelectBackupButton.IsEnabled = true;
            RecoverButton.IsEnabled = _backupPath is not null;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cancellation?.Cancel();
    }

    private async void OpenMarkdown_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        await LaunchValidatedOutputAsync(output => output.MarkdownReport);
    }

    private async void OpenHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        await LaunchValidatedOutputAsync(output => output.HtmlReport);
    }

    private async void RevealOutput_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        try
        {
            using var validated = RecoveryCoordinator.ValidateCompletedOutput(
                _completedOutput.OutputRoot);
            var folder = await StorageFolder.GetFolderFromPathAsync(validated.OutputRoot);
            if (!await Launcher.LaunchFolderAsync(folder)) throw new InvalidOperationException();
        }
        catch
        {
            ShowOpenFailure();
        }
    }

    private async Task LaunchValidatedOutputAsync(Func<ValidatedRecoveryOutput, string> selectedPath)
    {
        if (_completedOutput is null) return;
        try
        {
            using var validated = RecoveryCoordinator.ValidateCompletedOutput(
                _completedOutput.OutputRoot);
            await LaunchPrivateFileAsync(selectedPath(validated));
        }
        catch
        {
            ShowOpenFailure();
        }
    }

    private async Task LaunchPrivateFileAsync(string path)
    {
        try
        {
            var file = await StorageFile.GetFileFromPathAsync(path);
            if (!await Launcher.LaunchFileAsync(file)) throw new InvalidOperationException();
        }
        catch
        {
            throw new InvalidOperationException();
        }
    }

    private void ShowOpenFailure()
    {
        StatusBar.Severity = InfoBarSeverity.Warning;
        StatusBar.Title = "Private report retained";
        StatusBar.Message = "Windows could not open the validated private result. The recovery was not deleted.";
    }
}
