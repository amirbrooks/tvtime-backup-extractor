using Microsoft.UI.Xaml.Controls;

namespace TVTimeRecovery.Windows;

// The real WinUI XAML compiler generates these members on Windows. This
// compile-only partial keeps the handwritten C# checked against the actual
// locked Windows App SDK reference assemblies on non-Windows build hosts.
public partial class App
{
    private void InitializeComponent() { }
}

public sealed partial class MainWindow
{
    private readonly ComboBox SourceKind = new();
    private readonly TextBlock SelectionStatus = new();
    private readonly Button RecoverButton = new();
    private readonly Button SelectBackupButton = new();
    private readonly Button CancelButton = new();
    private readonly PasswordBox BackupPassword = new();
    private readonly CheckBox SensitiveConfirmation = new();
    private readonly InfoBar StatusBar = new();
    private readonly StackPanel ResultActions = new();

    private void InitializeComponent() { }
}
