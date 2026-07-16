using System.Windows;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;

namespace AssessmentTool.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel(
            new CollectionViewModel(new UnavailableCollectionWorkflowService()),
            App.ToggleTheme);
    }
}
