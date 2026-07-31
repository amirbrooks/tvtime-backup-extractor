using Microsoft.UI.Xaml;

namespace TVTimeRecovery.Windows;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += (_, args) =>
        {
            RecoveryDiagnostics.Record(RecoveryDiagnostic.UnrecognizedFailure);
            args.Handled = false;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        _window.Activate();
    }
}
